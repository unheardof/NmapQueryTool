#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

read -p "Have you incremented the verison number in setup.py (y|n)? " answer

if [[ "$answer" != "y" && "$answer" != "Y" ]]; then
    exit
fi

rm -rf "$SCRIPT_DIR/dist/"
python3 setup.py sdist bdist_wheel
twine upload dist/*


