
import sys
import json

import web3
import eth_account


API_ENDPOINT = 'http://127.0.0.1:9001'
w3 = web3.Web3(web3.Web3.HTTPProvider(API_ENDPOINT+'/'))

# contract_abi = '''[
#     {
#         "constant": true,
#         "inputs": [],
#         "name": "name",
#         "outputs": [
#             {
#                 "name": "",
#                 "type": "string"
#             }
#         ],
#         "payable": false,
#         "stateMutability": "view",
#         "type": "function"
#     },
#     {
#         "constant": false,
#         "inputs": [
#             {
#                 "name": "_spender",
#                 "type": "address"
#             },
#             {
#                 "name": "_value",
#                 "type": "uint256"
#             }
#         ],
#         "name": "approve",
#         "outputs": [
#             {
#                 "name": "",
#                 "type": "bool"
#             }
#         ],
#         "payable": false,
#         "stateMutability": "nonpayable",
#         "type": "function"
#     },
#     {
#         "constant": true,
#         "inputs": [],
#         "name": "totalSupply",
#         "outputs": [
#             {
#                 "name": "",
#                 "type": "uint256"
#             }
#         ],
#         "payable": false,
#         "stateMutability": "view",
#         "type": "function"
#     },
#     {
#         "constant": false,
#         "inputs": [
#             {
#                 "name": "_from",
#                 "type": "address"
#             },
#             {
#                 "name": "_to",
#                 "type": "address"
#             },
#             {
#                 "name": "_value",
#                 "type": "uint256"
#             }
#         ],
#         "name": "transferFrom",
#         "outputs": [
#             {
#                 "name": "",
#                 "type": "bool"
#             }
#         ],
#         "payable": false,
#         "stateMutability": "nonpayable",
#         "type": "function"
#     },
#     {
#         "constant": true,
#         "inputs": [],
#         "name": "decimals",
#         "outputs": [
#             {
#                 "name": "",
#                 "type": "uint8"
#             }
#         ],
#         "payable": false,
#         "stateMutability": "view",
#         "type": "function"
#     },
#     {
#         "constant": true,
#         "inputs": [
#             {
#                 "name": "_owner",
#                 "type": "address"
#             }
#         ],
#         "name": "balanceOf",
#         "outputs": [
#             {
#                 "name": "balance",
#                 "type": "uint256"
#             }
#         ],
#         "payable": false,
#         "stateMutability": "view",
#         "type": "function"
#     },
#     {
#         "constant": true,
#         "inputs": [],
#         "name": "symbol",
#         "outputs": [
#             {
#                 "name": "",
#                 "type": "string"
#             }
#         ],
#         "payable": false,
#         "stateMutability": "view",
#         "type": "function"
#     },
#     {
#         "constant": false,
#         "inputs": [
#             {
#                 "name": "_to",
#                 "type": "address"
#             },
#             {
#                 "name": "_value",
#                 "type": "uint256"
#             }
#         ],
#         "name": "transfer",
#         "outputs": [
#             {
#                 "name": "",
#                 "type": "bool"
#             }
#         ],
#         "payable": false,
#         "stateMutability": "nonpayable",
#         "type": "function"
#     },
#     {
#         "constant": true,
#         "inputs": [
#             {
#                 "name": "_owner",
#                 "type": "address"
#             },
#             {
#                 "name": "_spender",
#                 "type": "address"
#             }
#         ],
#         "name": "allowance",
#         "outputs": [
#             {
#                 "name": "",
#                 "type": "uint256"
#             }
#         ],
#         "payable": false,
#         "stateMutability": "view",
#         "type": "function"
#     },
#     {
#         "payable": true,
#         "stateMutability": "payable",
#         "type": "fallback"
#     },
#     {
#         "anonymous": false,
#         "inputs": [
#             {
#                 "indexed": true,
#                 "name": "owner",
#                 "type": "address"
#             },
#             {
#                 "indexed": true,
#                 "name": "spender",
#                 "type": "address"
#             },
#             {
#                 "indexed": false,
#                 "name": "value",
#                 "type": "uint256"
#             }
#         ],
#         "name": "Approval",
#         "type": "event"
#     },
#     {
#         "anonymous": false,
#         "inputs": [
#             {
#                 "indexed": true,
#                 "name": "from",
#                 "type": "address"
#             },
#             {
#                 "indexed": true,
#                 "name": "to",
#                 "type": "address"
#             },
#             {
#                 "indexed": false,
#                 "name": "value",
#                 "type": "uint256"
#             }
#         ],
#         "name": "Transfer",
#         "type": "event"
#     }
# ]'''

erc20_abi = '''[
    {
        "constant": true,
        "inputs": [],
        "name": "name",
        "outputs": [
            {"name": "", "type": "string"}
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": false,
        "inputs": [
            {"name": "_name", "type": "string"},
            {"name": "_symbol", "type": "string"},
            {"name": "_decimals", "type": "uint8"},
            {"name": "_address", "type": "address"}
        ],
        "name": "init",
        "outputs": [ {"name": "", "type": "bool"} ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": false,
        "inputs": [
            {"name": "_spender", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "approve",
        "outputs": [ {"name": "", "type": "bool"} ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [],
        "name": "totalSupply",
        "outputs": [
            {"name": "", "type": "uint256"}
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": false,
        "inputs": [
            {"name": "_from", "type": "address"},
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "transferFrom",
        "outputs": [
            {"name": "", "type": "bool"}
        ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [],
        "name": "decimals",
        "outputs": [
            {"name": "", "type": "uint8"}
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [
            {"name": "_owner", "type": "address"}
        ],
        "name": "balanceOf",
        "outputs": [
            {"name": "balance", "type": "uint256"}
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [],
        "name": "symbol",
        "outputs": [
            {"name": "", "type": "string"}
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": false,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "transfer",
        "outputs": [
            {"name": "", "type": "bool"}
        ],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [
            {"name": "_owner", "type": "address"},
            {"name": "_spender", "type": "address"}
        ],
        "name": "allowance",
        "outputs": [
            {"name": "", "type": "uint256"}
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "mint",
        "outputs": [],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    }
]'''


staking_abi = '''[
    {
        "constant": true,
        "inputs": [
            {"name": "_owner", "type": "address"},
            {"name": "_spender", "type": "address"}
        ],
        "name": "unstake",
        "outputs": [
            {"name": "", "type": "uint256"}
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [
            {"name": "_value", "type": "uint256"}
        ],
        "name": "stake",
        "outputs": [],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
    }
]'''


keyfile_name = sys.argv[1]
try:
    f = open(keyfile_name, 'rt')
    keyfile_json = f.read()
    f.close()
    keyfile_dict = json.loads(keyfile_json)
    account_key = eth_account.account.decode_keyfile_json(keyfile_dict, password=b'')
    account = eth_account.Account.from_key(account_key)
    print('account read', account.address)

except:
    account = eth_account.Account.create()
    print('account create', account.address)
    keyfile_dict = eth_account.account.create_keyfile_json(private_key=account.key, password=b'')
    f = open(keyfile_name, 'wt')
    keyfile_json = json.dumps(keyfile_dict)
    f.write(keyfile_json)
    f.close()

# print('keyfile_json', keyfile_json)

erc20 = w3.eth.contract(address='0x0000000000000000000000000000000000000001', abi=erc20_abi)
staking = w3.eth.contract(address='0x0000000000000000000000000000000000000002', abi=staking_abi)


nonce = w3.eth.get_transaction_count(account.address)
print(nonce)
for action in sys.argv[2:]:
    if action == 'init':
        unsigned_tx = erc20.functions.init('BitPOW', 'KB', 3, account.address).build_transaction({
            'from': account.address,
            'nonce': nonce,
        })
        # print(unsigned_tx)
        signed_tx = w3.eth.account.sign_transaction(unsigned_tx, private_key=account.key)
        # print(signed_tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

    elif action == 'mint':
        unsigned_tx = erc20.functions.mint(account.address, 1000).build_transaction({
            'from': account.address,
            'nonce': nonce,
        })
        # print(unsigned_tx)
        signed_tx = w3.eth.account.sign_transaction(unsigned_tx, private_key=account.key)
        # print(signed_tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

    elif action == 'balance':
        balance = erc20.functions.balanceOf(account.address).call()
        print('balance', balance)

    elif action == 'totalsupply':
        totalsupply = erc20.functions.totalSupply().call()
        print('totalsupply', totalsupply)

    elif action == 'approve':
        unsigned_tx = erc20.functions.approve('0x0000000000000000000000000000000000000002', 1000).build_transaction({
            'from': account.address,
            'nonce': nonce,
        })
        # print(unsigned_tx)
        signed_tx = w3.eth.account.sign_transaction(unsigned_tx, private_key=account.key)
        # print(signed_tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

    elif action == 'allowance':
        allowance = erc20.functions.allowance(account.address, account.address).call()
        print('allowance', allowance)

    elif action == 'transfer':
        unsigned_tx = erc20.functions.transfer('0x0000000000000000000000000000000000000002', 1000).build_transaction({
            'from': account.address,
            'nonce': nonce,
        })
        # print(unsigned_tx)
        signed_tx = w3.eth.account.sign_transaction(unsigned_tx, private_key=account.key)
        # print(signed_tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)


    elif action == 'stake':
        unsigned_tx = staking.functions.stake(1000).build_transaction({
            'from': account.address,
            'nonce': nonce,
        })
        # print(unsigned_tx)
        signed_tx = w3.eth.account.sign_transaction(unsigned_tx, private_key=account.key)
        # print(signed_tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

    nonce += 1
