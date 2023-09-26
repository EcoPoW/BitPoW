
import math

import web3
import rlp
import eth_account
import eth_utils


V_OFFSET = 27
def eth_rlp2list(tx_rlp_bytes):
    if tx_rlp_bytes.startswith(b'\x02'):
        tx_rlp_list = rlp.decode(tx_rlp_bytes[1:])
        print('eth_rlp2list type2', tx_rlp_list)
        chain_id = int.from_bytes(tx_rlp_list[0], 'big')
        nonce = int.from_bytes(tx_rlp_list[1], 'big')
        gas_price = int.from_bytes(tx_rlp_list[2], 'big')
        max_priority = int.from_bytes(tx_rlp_list[3], 'big')
        max_fee = int.from_bytes(tx_rlp_list[4], 'big')
        to = web3.Web3.to_checksum_address(tx_rlp_list[5])
        value = int.from_bytes(tx_rlp_list[6], 'big')
        data = tx_rlp_list[7].hex()
        # print(tx_rlp_list[5])
        v = int.from_bytes(tx_rlp_list[9], 'big')
        r = int.from_bytes(tx_rlp_list[10], 'big')
        s = int.from_bytes(tx_rlp_list[11], 'big')
        # chain_id, chain_naive_v = eth_account._utils.signing.extract_chain_id(v)
        # print(chain_id, chain_naive_v)
        # if not chain_id:
        # v_standard = chain_naive_v - V_OFFSET
        return [chain_id, nonce, gas_price, max_priority, max_fee, to, value, data], [v, r, s]

    else:
        tx_rlp_list = rlp.decode(tx_rlp_bytes)
        print('eth_rlp2list', tx_rlp_list)
        nonce = int.from_bytes(tx_rlp_list[0], 'big')
        gas_price = int.from_bytes(tx_rlp_list[1], 'big')
        gas = int.from_bytes(tx_rlp_list[2], 'big')
        to = web3.Web3.to_checksum_address(tx_rlp_list[3])
        value = int.from_bytes(tx_rlp_list[4], 'big')
        data = tx_rlp_list[5].hex()
        # print(tx_rlp_list[5])
        v = int.from_bytes(tx_rlp_list[6], 'big')
        r = int.from_bytes(tx_rlp_list[7], 'big')
        s = int.from_bytes(tx_rlp_list[8], 'big')
        chain_id, chain_naive_v = eth_account._utils.signing.extract_chain_id(v)
        v_standard = chain_naive_v - V_OFFSET
        return [nonce, gas_price, gas, to, value, data, chain_id], [v_standard, r, s]


def hash_of_eth_tx_list(tx_list):
    print('hash_of_eth_tx_list', tx_list)
    if len(tx_list) == 8:
        chain_id = tx_list[0].to_bytes(math.ceil(tx_list[0].bit_length()/8), 'big')
        nonce = tx_list[1].to_bytes(math.ceil(tx_list[1].bit_length()/8), 'big')
        gas_price = tx_list[2].to_bytes(math.ceil(tx_list[2].bit_length()/8), 'big')
        max_priority = tx_list[3].to_bytes(math.ceil(tx_list[3].bit_length()/8), 'big')
        max_fee = tx_list[4].to_bytes(math.ceil(tx_list[4].bit_length()/8), 'big')
        to = bytes.fromhex(tx_list[5].replace('0x', ''))
        value = tx_list[6].to_bytes(math.ceil(tx_list[6].bit_length()/8), 'big')
        data = bytes.fromhex(tx_list[7].replace('0x', ''))
        # print([nonce, gas_price, gas, to, value, data, chain_id, 0, 0])
        rlp_bytes = rlp.encode([chain_id, nonce, gas_price, max_priority, max_fee, to, value, data, []])
        # print('raw', rlp_bytes)
        rlp_hash = eth_utils.keccak(b'\x02'+rlp_bytes)
        # print('hash1', rlp_hash)
        return rlp_hash

    else:
        nonce = tx_list[0].to_bytes(math.ceil(tx_list[0].bit_length()/8), 'big')
        gas_price = tx_list[1].to_bytes(math.ceil(tx_list[1].bit_length()/8), 'big')
        gas = tx_list[2].to_bytes(math.ceil(tx_list[2].bit_length()/8), 'big')
        to = bytes.fromhex(tx_list[3].replace('0x', ''))
        value = tx_list[4].to_bytes(math.ceil(tx_list[4].bit_length()/8), 'big')
        data = bytes.fromhex(tx_list[5].replace('0x', ''))
        chain_id = tx_list[6].to_bytes(math.ceil(tx_list[6].bit_length()/8), 'big')
        # print([nonce, gas_price, gas, to, value, data, chain_id, 0, 0])
        rlp_bytes = rlp.encode([nonce, gas_price, gas, to, value, data, chain_id, 0, 0])
        # print('raw', rlp_bytes)
        rlp_hash = eth_utils.keccak(rlp_bytes)
        # print('hash1', rlp_hash)
        return rlp_hash

