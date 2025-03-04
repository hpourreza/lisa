# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import copy
import functools
from typing import Any, Dict, List, Set

from lisa import schema
from lisa.parameter_parser.runbook import RunbookBuilder
from lisa.util import LisaException, constants, subclasses
from lisa.util.logger import get_logger
from lisa.variable import VariableEntry, merge_variables, replace_variables

_get_init_logger = functools.partial(get_logger, "init", "transformer")


class Transformer(subclasses.BaseClassWithRunbookMixin):
    def __init__(
        self,
        runbook: schema.Transformer,
        runbook_builder: RunbookBuilder,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(runbook, *args, **kwargs)
        self.name = runbook.name
        self.prefix = runbook.prefix
        self.depends_on = runbook.depends_on
        self.rename = runbook.rename

        self._runbook_builder = runbook_builder
        self._log = get_logger("transformer", self.name)

    def run(self, is_dry_run: bool = False) -> Dict[str, VariableEntry]:
        """
        Call by the transformer flow, don't override it in subclasses.
        """
        if is_dry_run:
            # create mock up variables and validate
            output_names = self._output_names
            # add prefix
            variables = {x: VariableEntry(x, "mock value") for x in output_names}
        else:
            self._log.info("transformer is running.")
            variables = self._internal_run()

        results: Dict[str, VariableEntry] = dict()
        unmatched_rename = copy.copy(self.rename)
        for name, value in variables.items():
            name = f"{self.prefix}_{name}"
            if name in self.rename:
                del unmatched_rename[name]
                name = self.rename[name]
            results[name] = VariableEntry(name, value)
        if unmatched_rename:
            raise LisaException(f"unmatched rename variable: {unmatched_rename}")
        return results

    @property
    def _output_names(self) -> List[str]:
        """
        List names of outputs, which are returned after run. It uses for
        pre-validation before the real run. It helps identifying variable name
        errors early.
        """
        raise NotImplementedError()

    def _internal_run(self) -> Dict[str, Any]:
        """
        The logic to transform
        """
        raise NotImplementedError()


def _sort(transformers: List[schema.Transformer]) -> List[schema.Transformer]:
    visited: Set[str] = set()
    all: Dict[str, schema.Transformer] = {}
    sorted_transformers: List[schema.Transformer] = []

    # construct full set and check duplicates
    for transformer in transformers:
        if transformer.name in all:
            raise LisaException(
                f"found duplicate transformers: '{transformer.name}', "
                f"use different names for them."
            )
        all[transformer.name] = transformer

    # build new sorted results
    for transformer in transformers:
        if transformer.name not in visited:
            _sort_dfs(all, transformer, visited, sorted_transformers)

    # check cycle reference
    referenced: Set[str] = set()
    for transformer in sorted_transformers:
        for item in transformer.depends_on:
            if item not in referenced:
                raise LisaException(
                    f"found cycle dependented transformers: "
                    f"'{transformer.name}' and '{item}'"
                )
        referenced.add(transformer.name)

    return sorted_transformers


def _sort_dfs(
    transformers: Dict[str, schema.Transformer],
    transformer: schema.Transformer,
    visited: Set[str],
    sorted_transformers: List[schema.Transformer],
) -> None:
    visited.add(transformer.name)
    for item in transformer.depends_on:
        if item not in visited:
            dependent = transformers.get(item, None)
            if not dependent:
                raise LisaException(
                    f"transformer '{transformer.name}' "
                    f"depends on non-existing transformer "
                    f"'{item}'"
                )
            _sort_dfs(transformers, dependent, visited, sorted_transformers)
    sorted_transformers.append(transformer)


def _run_transformers(
    runbook_builder: RunbookBuilder,
    is_dry_run: bool = False,
) -> Dict[str, VariableEntry]:
    root_runbook_data = runbook_builder.raw_data
    transfromers_data: List[Any] = root_runbook_data[constants.TRANSFORMER]
    assert isinstance(transfromers_data, list), "transfomer in runbook must be a list"

    transformers_runbook: List[schema.Transformer] = []
    for runbook_data in transfromers_data:
        # get base transformer runbook for replacing variables.
        runbook: schema.Transformer = schema.Transformer.schema().load(  # type: ignore
            runbook_data
        )

        if runbook.enabled:
            transformers_runbook.append(runbook)

    # resort the runbooks, and it's used in real run
    transformers_runbook = _sort(transformers_runbook)

    copied_variables: Dict[str, VariableEntry] = dict()
    for value in runbook_builder.variables.values():
        copied_variables[value.name] = value.copy()

    factory = subclasses.Factory[Transformer](Transformer)
    for runbook in transformers_runbook:
        # serialize to data for replacing variables
        runbook_data = runbook.to_dict()  # type: ignore

        # replace to validate all variables exist
        replace_variables(runbook_data, copied_variables)

        # revert to runbook
        runbook = schema.Transformer.schema().load(runbook_data)  # type: ignore

        derived_builder = runbook_builder.derive(copied_variables)
        transformer = factory.create_by_runbook(
            runbook=runbook, runbook_builder=derived_builder
        )
        values = transformer.run(is_dry_run=is_dry_run)
        merge_variables(copied_variables, values)

    return copied_variables


def run(runbook_builder: RunbookBuilder) -> None:
    log = _get_init_logger()

    root_runbook_data = runbook_builder.raw_data
    if constants.TRANSFORMER not in root_runbook_data:
        log.debug("no transfomer found, skipped")
        return

    # verify the variable is enough to next transformers and the whole runbook.
    # the validation without real run can save time, and fail fast on variable
    # mismatched.
    log.debug("dry run transformers...")
    mock_variables = _run_transformers(runbook_builder, is_dry_run=True)
    dry_run_root_runbook = copy.deepcopy(root_runbook_data)
    replace_variables(dry_run_root_runbook, mock_variables)

    # real run
    log.debug("running transformers...")
    output_variables = _run_transformers(runbook_builder)
    merge_variables(runbook_builder.variables, output_variables)
