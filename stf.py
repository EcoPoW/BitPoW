import hashlib
import copy

def subchain_stf(state, msg):
    new_state = copy.deepcopy(state)
    if msg.get('type') == 'folder_storage':
        folder = msg.get('name')
        assert folder
        new_state.setdefault('folder_storage', {})
        current_folder = new_state['folder_storage'].setdefault(folder, {})
        # print('current folder', current_folder)
        if 'remove' in msg:
            remove_dict = msg['remove']
            for path, info in remove_dict.items():
                # print('remove', path, info)
                assert path in current_folder and info == current_folder[path]
                del current_folder[path]

        if 'add' in msg:
            add_dict = msg['add']
            for path, info in add_dict.items():
                # print('add', path, info)
                assert path not in current_folder
                current_folder[path] = info
        # print('fullstate dict', fullstate_dict)

    return new_state

def chain_stf(state, data):
    subchains = state.get('subchains', {})
    subchains.update(data.get('subchains', {}))
    new_state = {}
    new_state['subchains'] = subchains
    return new_state

def chain_block_validator(block, new_block):
    pass
