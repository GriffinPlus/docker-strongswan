#!/bin/bash

# determine the absolute path of the executing script and the directory it is in
SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_DIRECTORY_PATH=$(dirname "$SCRIPT_PATH")

set -e

# backup working directory
pushd "$SCRIPT_DIRECTORY_PATH"

# create virtual environment
python3 -m venv "${SCRIPT_DIRECTORY_PATH}/.venv"

# enter virtual environment
source .venv/bin/activate

# install test runner
pip3 install -r requirements.txt

# execute tests
docker-compose -f docker-compose.default.yml up -d
sleep 30
nose2
docker-compose -f docker-compose.default.yml down

# exit virtual environment
deactivate

# restore working directory
popd
