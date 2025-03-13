<div align="center">
    <img src="https://github.com/viur-framework/viur-artwork/raw/main/icons/icon-toolkit.svg" height="196" alt="A hexagonal logo of Toolkit" title="Toolkit logo"/>
    <h1>viur-toolkit</h1>
    <a href="https://pypi.org/project/viur-toolkit/">
        <img alt="Badge showing current PyPI version" title="PyPI" src="https://img.shields.io/pypi/v/viur-toolkit">
    </a>
    <a href="LICENSE">
        <img src="https://img.shields.io/github/license/viur-framework/viur-toolkit" alt="Badge displaying the license" title="License badge">
    </a>
    <br>
    A kit of helpers and tools to simplify more intensive use of ViUR
</div>

## Usage

### Install with pip
```
pip install viur-toolkit
```

### Install with pipenv
```
pipenv install viur-toolkit
```

### Example
```python
from viur import toolkit

if toolkit.user_has_access("root"):
    print("Hello root user!")
```


## Development / Contributing

Create a fork and clone it

### Setup the local environment with pipenv:
```sh
cd viur-toolkit
pipenv install --dev
pipenv run precommit_install
```

### Install as editable in your project
```sh
cd myproject
pipenv install -e path/to/viur-toolkit
```

### Code linting & type checking
Use the `lint` command
```sh
$ pipenv run lint
```
tu run `pep8check` and `type_check` at once.

#### Alternative:
Setup the pre-commit hook with `pipenv run precommit_install`.

### Branches
Depending on what kind of change your Pull Request contains, please submit your PR against the following branches:

* **main:**
  fixes/patches that fix a problem with existing code go into this branch.
  This results in a new patch version (X.X.n+1 where n is the current patch-level).
* **develop:**
  new features, refactorings, or adjustments for new versions of dependencies are added to this branch.
  This becomes a new minor version (X.n+1.0) where n is the current minor-level).
  Depending on the complexity of the changes, a new major release (n+1.0.0, where n is the current major level) may be chosen instead.
