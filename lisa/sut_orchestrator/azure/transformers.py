# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from time import sleep
from typing import Any, Dict, List, Type

from azure.mgmt.compute.models import GrantAccessData  # type: ignore
from dataclasses_json import dataclass_json
from retry import retry

from lisa import schema
from lisa.environment import Environments, EnvironmentSpace
from lisa.feature import Features
from lisa.features import StartStop
from lisa.node import RemoteNode
from lisa.parameter_parser.runbook import RunbookBuilder
from lisa.platform_ import load_platform_from_builder
from lisa.transformer import Transformer
from lisa.util import LisaException, constants, get_date_str, get_datetime_path
from lisa.util.perf_timer import create_timer

from .common import (
    AZURE_SHARED_RG_NAME,
    check_or_create_storage_account,
    get_compute_client,
    get_environment_context,
    get_network_client,
    get_node_context,
    get_or_create_storage_container,
    get_storage_account_name,
    wait_operation,
)
from .platform_ import AzurePlatform
from .tools import Waagent

DEFAULT_VHD_CONTAINER_NAME = "lisa-vhd-cache"
DEFAULT_VHD_SUBFIX = "exported"


@retry(tries=10, jitter=(1, 2))
def _generate_vhd_path(container_client: Any, file_name_part: str = "") -> str:
    path = PurePosixPath(
        f"{get_date_str()}/{get_datetime_path()}_"
        f"{DEFAULT_VHD_SUBFIX}_{file_name_part}.vhd"
    )
    blobs = container_client.list_blobs(name_starts_with=path)
    for _ in blobs:
        raise LisaException(f"blob exists already: {path}")
    return str(path)


@dataclass_json
@dataclass
class VhdTransformerSchema(schema.Transformer):
    # resource group and vm name to be exported
    resource_group_name: str = field(
        default="", metadata=schema.metadata(required=True)
    )
    vm_name: str = "node-0"

    # values for SSH connection. public_address is optional, because it can be
    # retrieved from vm_name. Others can be retrieved from platform.
    public_address: str = ""
    public_port: int = 22
    username: str = constants.DEFAULT_USER_NAME
    password: str = ""
    private_key_file: str = ""

    # values for exported vhd. storage_account_name is optional, because it can
    # be the default storage of LISA.
    storage_account_name: str = ""
    container_name: str = DEFAULT_VHD_CONTAINER_NAME
    file_name_part: str = ""

    # restore environment or not
    restore: bool = False


@dataclass_json
@dataclass
class DeployTransformerSchema(schema.Transformer):
    requirement: schema.Capability = field(default_factory=schema.Capability)
    resource_group_name: str = ""


@dataclass_json
@dataclass
class DeleteTransformerSchema(schema.Transformer):
    resource_group_name: str = field(
        default="", metadata=schema.metadata(required=True)
    )


class VhdTransformer(Transformer):
    """
    convert an azure VM to VHD, which is ready to deploy.
    """

    __url_name = "url"

    @classmethod
    def type_name(cls) -> str:
        return "azure_vhd"

    @classmethod
    def type_schema(cls) -> Type[schema.TypedSchema]:
        return VhdTransformerSchema

    @property
    def _output_names(self) -> List[str]:
        return [self.__url_name]

    def _internal_run(self) -> Dict[str, Any]:
        runbook: VhdTransformerSchema = self.runbook
        platform = _load_platform(self._runbook_builder, self.type_name())

        compute_client = get_compute_client(platform)
        virtual_machine = compute_client.virtual_machines.get(
            runbook.resource_group_name, runbook.vm_name
        )

        node = self._prepare_virtual_machine(platform, virtual_machine)

        vhd_location = self._export_vhd(platform, virtual_machine)

        self._restore_vm(platform, virtual_machine, node)

        return {self.__url_name: vhd_location}

    def _prepare_virtual_machine(
        self, platform: AzurePlatform, virtual_machine: Any
    ) -> RemoteNode:
        runbook: VhdTransformerSchema = self.runbook
        if not runbook.public_address:
            runbook.public_address = self._get_public_ip_address(
                platform, virtual_machine
            )

        platform_runbook: schema.Platform = platform.runbook

        if not runbook.username:
            runbook.username = platform_runbook.admin_username
        if not runbook.password:
            runbook.password = platform_runbook.admin_password
        if not runbook.private_key_file:
            runbook.private_key_file = platform_runbook.admin_private_key_file

        node_runbook = schema.RemoteNode(
            name=runbook.vm_name,
            public_address=runbook.public_address,
            port=runbook.public_port,
            username=runbook.username,
            password=runbook.password,
            private_key_file=runbook.private_key_file,
        )
        node = RemoteNode(
            runbook=node_runbook, index=0, logger_name=f"{self.type_name()}_vm"
        )
        node.features = Features(node, platform)
        node_context = get_node_context(node)
        node_context.vm_name = runbook.vm_name
        node_context.resource_group_name = runbook.resource_group_name

        node.set_connection_info_by_runbook()
        node.initialize()

        # prepare vm for exporting
        wa = node.tools[Waagent]
        node.execute("export HISTSIZE=0", shell=True)
        wa.deprovision()

        # stop the vm
        startstop = node.features[StartStop]
        startstop.stop()

        return node

    def _export_vhd(self, platform: AzurePlatform, virtual_machine: Any) -> str:
        runbook: VhdTransformerSchema = self.runbook
        compute_client = get_compute_client(platform)

        # generate sas url from os disk, so it can be copied.
        self._log.debug("generating sas url...")
        location = virtual_machine.location
        os_disk_name = virtual_machine.storage_profile.os_disk.name
        operation = compute_client.disks.begin_grant_access(
            resource_group_name=runbook.resource_group_name,
            disk_name=os_disk_name,
            grant_access_data=GrantAccessData(access="Read", duration_in_seconds=86400),
        )
        wait_operation(operation)
        sas_url = operation.result().access_sas
        assert sas_url, "cannot get sas_url from os disk"

        self._log.debug("getting or creating storage account and container...")
        # get vhd container
        if not runbook.storage_account_name:
            runbook.storage_account_name = get_storage_account_name(
                subscription_id=platform.subscription_id, location=location, type="t"
            )

        check_or_create_storage_account(
            credential=platform.credential,
            subscription_id=platform.subscription_id,
            account_name=runbook.storage_account_name,
            resource_group_name=AZURE_SHARED_RG_NAME,
            location=location,
            log=self._log,
        )
        container_client = get_or_create_storage_container(
            runbook.storage_account_name, runbook.container_name, platform.credential
        )

        path = _generate_vhd_path(container_client, runbook.file_name_part)
        vhd_path = f"{container_client.url}/{path}"
        self._log.info(f"copying vhd: {vhd_path}")
        blob_client = container_client.get_blob_client(path)
        operation = blob_client.start_copy_from_url(
            sas_url, metadata=None, incremental_copy=False
        )

        timeout_timer = create_timer()
        timeout = 60 * 30
        while timeout_timer.elapsed(False) < timeout:
            props = blob_client.get_blob_properties()
            if props.copy.status == "success":
                break
            # the copy is very slow, it may need several minutes. check it every
            # 2 seconds.
            sleep(2)
        if timeout_timer.elapsed() >= timeout:
            raise LisaException(f"wait copying VHD timeout: {vhd_path}")

        self._log.debug("vhd copied")

        return vhd_path

    def _restore_vm(
        self, platform: AzurePlatform, virtual_machine: Any, node: RemoteNode
    ) -> None:
        runbook: VhdTransformerSchema = self.runbook

        self._log.debug("restoring vm...")
        # release the vhd export lock, so it can be started back
        compute_client = get_compute_client(platform)
        os_disk_name = virtual_machine.storage_profile.os_disk.name
        operation = compute_client.disks.begin_revoke_access(
            resource_group_name=runbook.resource_group_name,
            disk_name=os_disk_name,
        )
        wait_operation(operation)

        if runbook.restore:
            start_stop = node.features[StartStop]
            start_stop.start()

    def _get_public_ip_address(
        self, platform: AzurePlatform, virtual_machine: Any
    ) -> str:
        runbook: VhdTransformerSchema = self.runbook
        for (
            network_interface_reference
        ) in virtual_machine.network_profile.network_interfaces:
            if network_interface_reference.primary:
                network_interface_name = network_interface_reference.id.split("/")[-1]
                break
        network_client = get_network_client(platform)
        network_interface = network_client.network_interfaces.get(
            runbook.resource_group_name, network_interface_name
        )

        for ip_config in network_interface.ip_configurations:
            if ip_config.public_ip_address:
                public_ip_name = ip_config.public_ip_address.id.split("/")[-1]
                break
        public_ip_address: str = network_client.public_ip_addresses.get(
            runbook.resource_group_name, public_ip_name
        ).ip_address

        assert (
            public_ip_address
        ), "cannot find public IP address, make sure the VM is in running status."

        return public_ip_address


class DeployTransformer(Transformer):
    """
    deploy a node in transformer phase for further operations
    """

    __resource_group_name = "resource_group_name"

    @classmethod
    def type_name(cls) -> str:
        return "azure_deploy"

    @classmethod
    def type_schema(cls) -> Type[schema.TypedSchema]:
        return DeployTransformerSchema

    @property
    def _output_names(self) -> List[str]:
        return [self.__resource_group_name]

    def _internal_run(self) -> Dict[str, Any]:
        platform = _load_platform(self._runbook_builder, self.type_name())
        runbook: DeployTransformerSchema = self.runbook

        envs = Environments()
        environment_requirement = EnvironmentSpace()
        environment_requirement.nodes.append(runbook.requirement)
        environment = envs.from_requirement(environment_requirement)
        assert environment

        platform.prepare_environment(environment=environment)

        platform.deploy_environment(environment)

        resource_group_name = get_environment_context(environment).resource_group_name

        return {self.__resource_group_name: resource_group_name}


class DeleteTransformer(Transformer):
    """
    delete an environment
    """

    @classmethod
    def type_name(cls) -> str:
        return "azure_delete"

    @classmethod
    def type_schema(cls) -> Type[schema.TypedSchema]:
        return DeleteTransformerSchema

    @property
    def _output_names(self) -> List[str]:
        return []

    def _internal_run(self) -> Dict[str, Any]:
        platform = _load_platform(self._runbook_builder, self.type_name())
        runbook: DeleteTransformerSchema = self.runbook

        # mock up environment for deletion
        envs = Environments()
        environment_requirement = EnvironmentSpace()
        environment_requirement.nodes.append(schema.NodeSpace())
        environment = envs.from_requirement(environment_requirement)
        assert environment
        environment_context = get_environment_context(environment)
        environment_context.resource_group_name = runbook.resource_group_name
        environment_context.resource_group_is_created = True

        platform.delete_environment(environment)

        return {}


def _load_platform(
    runbook_builder: RunbookBuilder, transformer_name: str
) -> AzurePlatform:
    platform = load_platform_from_builder(runbook_builder)
    assert isinstance(
        platform, AzurePlatform
    ), f"'{transformer_name}' support only Azure platform"

    platform.initialize()
    return platform
