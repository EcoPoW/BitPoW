import hashlib
import copy

import chain
import setting
import rpc

def tempchain_chat_stf(state, msg):
    print('state', state)
    data = msg[4]
    print('data', data)
    new_state = copy.deepcopy(state)
    if 'channel_id' not in new_state and 'channel_id' in data:
        new_state['channel_id'] = data['channel_id']
    assert new_state['channel_id'] == data['channel_id']

    if 'contacts' in data and len(data['contacts']) > 0:
        new_state.setdefault('contacts', []).extend(data['contacts'])
        if 'temp_contacts' in new_state:
            del new_state['temp_contacts']

    if 'temp_contacts' in data and len(data['temp_contacts']) > 0:
        new_state['temp_contacts'] = data['temp_contacts']

    if 'rekeys' in data:
        new_state.setdefault('rekeys', {})
        new_state['rekeys'].update(data['rekeys'])

    return new_state

def subchain_stf(state, msg):
    data = msg[chain.MSG_DATA]
    sender = msg[chain.SENDER]

    new_state = copy.deepcopy(state)
    # if 'eth_raw_tx' in data:
    #     raw_tx = data['eth_raw_tx']
    #     tx, tx_from, tx_to, _tx_hash = rpc.tx_info(raw_tx)
    #     balance = new_state.get('balances', {}).get('SHA', 10**15)
    #     print('balance', balance, tx.value)
    #     balance -= int(tx.value/10**18)
    #     new_state.setdefault('balances', {})
    #     new_state['balances']['SHA'] = balance

    if data.get('type') == 'new_asset':
        balances = new_state.get('balances', {})
        balances[data['creator']] = data['amount']
        new_state['balances'] = balances

    elif data.get('type') == 'send_asset':
        balances = new_state.get('balances', {})
        to = data.get('to')
        balances[sender] -= int(data['amount'])
        balances.setdefault(to, 0)
        balances[to] += int(data['amount'])
        new_state['balances'] = balances

    elif data.get('type') == 'folder_storage':
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

def chain_stf(state, block):
    data = copy.copy(block[chain.DATA])
    new_state = {}

    if 'nodes' in data:
        nodes = copy.copy(state.get('nodes', {}))

    if 'proofs' in data:
        proofs = copy.copy(state.get('proofs', {}))

    if 'subchains' in data:
        subchains = copy.copy(state.get('subchains', {}))
        subchains.update(data.get('subchains', {}))
        new_state['subchains'] = subchains

    tokens = copy.copy(state.get('tokens', {}))
    if 'tokens' in data:
        tokens.update(data.get('tokens', {}))
    new_state['tokens'] = tokens

    aliases = copy.copy(state.get('aliases', {}))
    if 'aliases' in data:
        aliases.update(data.get('aliases', {}))
    new_state['aliases'] = aliases

    balances_to_collect = state.get('balances_to_collect', {})
    if 'balances_to_collect' in data:
        for address, msg_hashes in data['balances_to_collect'].items():
            hashes = set(balances_to_collect.get(address, []))
            balances_to_collect[address] = list(hashes|msg_hashes)
    new_state['balances_to_collect'] = balances_to_collect

    return new_state

def chain_block_validator(block, new_block):
    pass
