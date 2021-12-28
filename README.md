# ByteChain
The introduction of ByteChain.

## Getting started

ByteChain is **python3** and requires the following libraries:
-six
-tornado==5.1.1
-eth_keys
-eth-hash[pycryptodome]
-python-rocksdb
-websocket-client
-requests
>You can install libraries using the pip install xxx(library name).
### Quickstart
Firstly, you need to clone the entire project from Github.
>git clone https://github.com/EcoPoW/ByteChain.git

You can then use the following command to quickly start the node:
> cd ByteChain
> python3 node.py --name xx --port 9001 --host 0.0.0.0

Open a browser and access **localhost:9001**, page displays information about the block.
