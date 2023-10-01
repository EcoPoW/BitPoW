
Ubuntu 22.04 LTS is recommended, try WSL if you are in Windows.

    sudo apt update
    sudo apt install python-is-python3 python3-pip python3-rocksdb
    pip install -r requirement.txt

Run the node:

    python node.py --name nodename --host 127.0.0.1 --port 8080

