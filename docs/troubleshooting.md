# Troubleshooting

- [Installation](#installation)
  - [How to use LISA in WSL](#how-to-use-lisa-in-wsl)
  - [Cannot find package after run \`poetry
    install\`](#cannot-find-package-after-run-poetry-install)
  - [Error: Poetry could not find a pyproject.toml
    file](#error-poetry-could-not-find-a-pyprojecttoml-file)
- [Using VSCode](#using-vscode)
  - [Cannot find Python Interpreter by
    Poetry](#cannot-find-python-interpreter-by-poetry)
  - [VSCode Python extension no longer supports "python.pythonPath" in
    "setting.json"](#vscode-python-extension-no-longer-supports-pythonpythonpath-in-settingjson)
- [Other issues](#other-issues)
  - [Poetry related questions](#poetry-related-questions)

## Installation

### How to use LISA in WSL

If you are using WSL, installing Poetry on both Windows and WSL may cause both
platforms' versions of Poetry to be on your path, as Windows binaries are mapped
into `PATH` of WSL. This means that the WSL `poetry` binary _must_ appear in
your `PATH` before the Windows version, otherwise this error will appear:

> `/usr/bin/env: ‘python\r’: No such file or directory`

### Cannot find package after run \`poetry install\`

Poetry is case sensitive, which means it differentiates directories like
`C:\abc` and `C:\ABC` in Windows, although Windows in fact does not allow this
(as a case insensitive system). When reading the path, please make sure there's
no case mismatch in the path.

### Error: Poetry could not find a pyproject.toml file

Poetry provides different packages according to the folder, and depends on the
`pyproject.toml` file in the current folder. Make sure to run `poetry` in the
root folder of LISA.

## Using VSCode

### Cannot find Python Interpreter by Poetry

In the root folder of LISA, run the command below. It will return the path of
the virtual environment that Poetry set up. Use that path to find the Python
interpreter accordingly (in most cases open the path and look for
`\Scripts\python.exe`).

```powershell
poetry env info -p
```

### VSCode Python extension no longer supports "python.pythonPath" in "setting.json"

> We removed the "python.pythonPath" setting from your settings.json file as the
> setting is no longer used by the Python extension. You can get the path of
> your selected interpreter in the Python output channel.

Refer to
[DeprecatePythonPath](https://github.com/microsoft/vscode-python/wiki/AB-Experiments)
for more information.

An alternative way is to simply select the Poetry Python interpreter as the
default interpreter in the workspace, as in [Cannot find Python Interpreter by
Poetry](#cannot-find-python-interpreter-by-poetry)

## Other issues

Please check [known issues](https://github.com/microsoft/lisa/issues) or [file a
new issue](https://github.com/microsoft/lisa/issues/new) if it doesn't exist.

### Poetry related questions

Poetry is very useful to manage dependencies of Python. It's a virtual
environment, not a complete interpreter like Conda. So make sure the right and
effective version of Python interpreter is installed. You can learn more about
Poetry in the official documentation like
[installation](https://python-poetry.org/docs/#installation) or
[commands](https://python-poetry.org/docs/cli/).
