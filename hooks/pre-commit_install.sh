#!/bin/env sh

set -e

path="$(git rev-parse --git-path hooks)/pre-commit"

if [ -w $path ]; then
    echo "$path exists already."
    echo "Overwrite? [y/N] "
    read ANSWER
    if [[ "$ANSWER" != "y" && "$ANSWER" != "Y" ]]; then
        echo "Aborted"
        exit 1
    fi
fi


cat > "$path" << EOL
#!/bin/env sh

# Redirect output to stderr.
exec 1>&2

echo "Running linter ..."
PIPENV_PIPFILE=$(pipenv --where)/Pipfile pipenv run lint
EOL

chmod +x "$path"

echo "Created pre-commit hook at $path"
