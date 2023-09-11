
import types

import eth_utils
import web3

import vm
import console

import contract_erc20
import contract_staking


def call(addr, fn, params):
    console.log(addr, fn, params)
    console.log(vm_map[addr])
    type_params = []
    for k, v in zip(type_map[addr][fn], params):
        print('type', k, v)
        if k == 'address':
            type_params.append(web3.Web3.to_checksum_address(v))
        elif k == 'uint256':
            type_params.append(v)

    vm_map[addr].run(type_params, fn)
    return


contract_map = {
    '0x0000000000000000000000000000000000000001': contract_erc20,
    '0x0000000000000000000000000000000000000002': contract_staking,
}

interface_map = {}
type_map = {}
vm_map = {}
for addr, contract in contract_map.items():
    interface_map[addr] = {}
    type_map[addr] = {}
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
            interface_map[addr]['0x'+eth_utils.keccak(func_sig.encode('utf8')).hex()[:8]] = v
            type_map[addr][k] = params

    v = vm.VM()
    v.import_module(contract)
    v.global_vars['print'] = console.prt
    v.global_vars['call'] = call
    vm_map[addr] = v

print(interface_map)
print(type_map)


# class Contract:
#     def __init__(self, addr):
#         self.addr = addr

#     # def __getattribute__(self, __name):
#     #     console.log(__name)
#     #     console.log(type_map[self.__dict__[addr]][__name])
#     #     return type_map[self.__dict__[addr]][__name]

#     def __getattr__(self, __name):
#         console.log(__name, contract_map[self.addr].__dict__[__name])
#         return contract_map[self.addr].__dict__[__name]
