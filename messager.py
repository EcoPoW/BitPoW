from __future__ import print_function

import sys
import os
import time
import pprint
# import random
import string
# import base64
import hashlib
import json

import requests
# import ecdsa
import eth_keys

import stf

def main():
    if len(sys.argv) < 2:
        print('''help:
  messager.py key
  messager.py host
  messager.py port
  messager.py enable
  messager.py disable
''')
        return



