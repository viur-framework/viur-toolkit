<div align="center">
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


## Development

Create a fork and clone it

### Setup the local environment with pipenv:
```sh
cd viur-toolkit
pipenv install --dev
```

### Install as editable in your project
```sh
cd myproject
pipenv install -e path/to/viur-toolkit
```

### Code linting & type checking

And use the `lint` command
```sh
$ pipenv run lint
```
tu run `pep8check` and `type_check` at once.
