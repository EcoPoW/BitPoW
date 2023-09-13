
import sys
import json

import web3
import eth_account


w3 = web3.Web3(web3.Web3.HTTPProvider('http://127.0.0.1:9001/'))

contract_abi = '''[
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

staking = w3.eth.contract(address='0x0000000000000000000000000000000000000002', abi=contract_abi)


nonce = w3.eth.get_transaction_count(account.address)
unsigned_tx = staking.functions.stake(1000).build_transaction({
    'from': account.address,
    'nonce': nonce,
})
# print(unsigned_tx)
signed_tx = w3.eth.account.sign_transaction(unsigned_tx, private_key=account.key)
# print(signed_tx)
tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
