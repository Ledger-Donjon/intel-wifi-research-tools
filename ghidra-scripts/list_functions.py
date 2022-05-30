# SPDX-License-Identifier: MIT

# Output addresses of "push_s blink" instructions.

import itertools

def match_j_blink(instruction, func_addr):
    if instruction.getMnemonicString() != "j_s" or instruction.getRegister(0).getName() != "blink":
        return False

    # skip null sub
    addr = instruction.getAddress().getUnsignedOffset()
    if addr == func_addr:
        return False

    return True

def match_push_blink(instruction, func_addr):
    return instruction.getMnemonicString() == "push_s" and instruction.getRegister(0).getName() == "blink"

def get_addresses(func, fnmatch):
    """
    Return a list of addresses from a function.

    The instructions at these addresses matches fnmatch.
    """

    func_body = func.getBody()
    func_addr = func.getEntryPoint().getUnsignedOffset()
    listing = currentProgram.getListing()

    addresses = []
    opiter = listing.getInstructions(func_body, True)
    while opiter.hasNext():
        instruction = opiter.next()
        if fnmatch(instruction, func_addr):
            addr = instruction.getAddress().getUnsignedOffset()
            addresses.append(addr)

    return addresses


fm = currentProgram.getFunctionManager()
funcs = fm.getFunctions(True)

addresses = [ get_addresses(func, match_push_blink) for func in funcs ]
addresses = itertools.chain.from_iterable(addresses)
addresses = list(set(addresses))
addresses.sort()

for addr in addresses:
    print("0x{0:x}".format(addr))
