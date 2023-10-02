
import types

import eth_utils
import web3

import vm
import console

import contract_erc20
import contract_erc721
import contract_staking


contract_map = {
    '0x0000000000000000000000000000000000000001': contract_erc20,
    '0x0000000000000000000000000000000000000002': contract_staking,
    '0x0000000000000000000000000000000000000003': contract_erc20,
    '0x0000000000000000000000000000000000000004': contract_erc721,
}

interface_map = {}
params_map = {}
return_map = {}
vm_map = {}
for addr, contract in contract_map.items():
    interface_map[addr] = {}
    params_map[addr] = {}
    return_map[addr] = {}
    for k, v in contract.__dict__.items():
        if not k.startswith('_') and type(v) in [types.FunctionType]:
            # print(k, type(v))
            # print(v.__code__.co_kwonlyargcount, v.__code__.co_posonlyargcount)
            # print(v.__code__.co_varnames[:v.__code__.co_argcount])
            # for i in v.__code__.co_varnames[:v.__code__.co_argcount]:
            #     print(v.__annotations__[i].__name__)
            params = [v.__annotations__[i].__name__ for i in v.__code__.co_varnames[:v.__code__.co_argcount]]
            func_sig = '%s(%s)' % (k, ','.join(params))
            # print(func_sig, '0x'+eth_utils.keccak(func_sig.encode('utf8')).hex()[:8])
            interface_map[addr][eth_utils.keccak(func_sig.encode('utf8')).hex()[:8]] = v
            params_map[addr][k] = params

            #console.log(k, v.__annotations__.get('return', None))
            return_type = v.__annotations__.get('return', None)
            return_map[addr][k] = return_type.__name__ if return_type else 'bool'

    v = vm.VM()
    v.import_module(contract)
    v.global_vars['print'] = console.prt
    # v.global_vars['_call'] = call
    vm_map[addr] = v

print(interface_map)
print(params_map)
