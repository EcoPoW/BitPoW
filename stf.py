import hashlib
import copy

import setting
import rpc

def subchain_stf(state, data):
    new_state = copy.deepcopy(state)
    if 'eth_raw_tx' in data:
        raw_tx = data['eth_raw_tx']
        tx, tx_from, tx_to, _tx_hash = rpc.tx_info(raw_tx)
        balance = new_state.get('balances', {}).get('SHA', 10**15)
        print('balance', balance, tx.value)
        balance -= int(tx.value/10**18)
        new_state.setdefault('balances', {})
        new_state['balances']['SHA'] = balance

    if data.get('type') == 'new_asset':
        # print('data -------', data)
        balances = new_state.get('balances', {})
        balances[data['name']] = data['amount']
        new_state['balances'] = balances
        # print('state -------', new_state)

    if data.get('type') == 'folder_storage':
        folder = data.get('name')
        assert folder
        new_state.setdefault('folder_storage', {})
        current_folder = new_state['folder_storage'].setdefault(folder, {})
        # print('current folder', current_folder)
        if 'remove' in data:
            remove_dict = data['remove']
            for path, info in remove_dict.items():
                # print('remove', path, info)
                assert path in current_folder and info == current_folder[path]
                del current_folder[path]

        if 'add' in data:
            add_dict = data['add']
            for path, info in add_dict.items():
                # print('add', path, info)
                assert path not in current_folder
                current_folder[path] = info
        # print('blockstate_ dict', blockstate_dict)

    if data.get('type') == 'chat_enable':
        new_state['chat_master_pk'] = data['chat_master_pk']

    if data.get('type') == 'chat_disable':
        if 'chat_master_pk' in new_state:
            del new_state['chat_master_pk']

    return new_state

def chain_stf(state, data):
    new_state = {}

    if 'nodes' in data:
        nodes = copy.copy(state.get('nodes', {}))

    if 'proofs' in data:
        proofs = copy.copy(state.get('ptoofs', {}))

    if 'subchains' in data:
        subchains = copy.copy(state.get('subchains', {}))
        subchains.update(data.get('subchains', {}))
        new_state['subchains'] = subchains

    tokens = copy.copy(state.get('tokens', {}))
    if 'tokens' in data:
        tokens.update(data.get('tokens', {}))
    new_state['tokens'] = tokens

    balances_to_collect = state.get('balances_to_collect', {})
    if 'balances_to_collect' in data:
        for address, msg_hashes in data['balances_to_collect'].items():
            hashes = set(balances_to_collect.get(address, []))
            balances_to_collect[address] = list(hashes|msg_hashes)
    new_state['balances_to_collect'] = balances_to_collect

    return new_state

def chain_block_validator(block, new_block):
    pass
