
import web3
import eth_account


w3 = web3.Web3(web3.Web3.HTTPProvider('http://127.0.0.1:9001/'))

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

contract_abi = '''[
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


erc20 = w3.eth.contract(address='0x0000000000000000000000000000000000000001', abi=contract_abi)
balance = erc20.functions.balanceOf('0x0000000000000000000000000000000000000001').call()
print(balance)
totalsupply = erc20.functions.totalSupply().call()
print(totalsupply)

# mint = erc20.functions.mint('0x0000000000000000000000000000000000000001', 1000).transact()
# print(mint)

account = eth_account.Account.create()
nonce = w3.eth.get_transaction_count(account.address)
unsigned_tx = erc20.functions.mint('0x0000000000000000000000000000000000000001', 1000).build_transaction({
    'from': account.address,
    'nonce': nonce,
})
print(unsigned_tx)
signed_tx = w3.eth.account.sign_transaction(unsigned_tx, private_key=account.key)
# print(signed_tx)
tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
