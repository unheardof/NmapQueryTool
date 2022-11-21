#!/usr/bin/env python3

from os import listdir
from os.path import isfile, isdir, join
import hashlib
import subprocess
import tst.integration_tests

tst.integration_tests.run_integration_tests()

# TODO: Run unit tests as well
