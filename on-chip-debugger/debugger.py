#!/usr/bin/env python3

import argparse
import enum
import logging
import signal
import time

from write_mem import remove_hook
import write_mem

class Cmd(enum.IntEnum):
    NONE         = 0
    CONTINUE     = 3
    READ_REG     = 4
    READ_MEM1    = 0x6789
    READ_MEM2    = 0x678a
    READ_MEM4    = 0x678b
    WRITE_MEM1   = 0x1234
    WRITE_MEM2   = 0x1235
    WRITE_MEM4   = 0x1236
    DISABLE_HOOK = 0xd34d

class Reg(enum.IntEnum):
    ARG1 = 0xA01E30
    ARG2 = 0xA01E34
    OUT  = 0xA03C3C
    PING = 0xA01E78 # & 0xffffff
    CMD  = 0xA01E7C # & 0xffffff

class Debugger:
    REGS_VALUE = {}

    def __init__(self):
        self.stop = False
        for reg in Reg:
            self.read_reg(reg)

        # if the hook was previously disabled, enable it
        if self.REGS_VALUE[Reg.CMD] == Cmd.DISABLE_HOOK:
            self.write_reg(Reg.CMD, 0xdeadbeef)

    def read_reg(self, reg: Reg):
        value = write_mem.read_reg(reg)
        self.REGS_VALUE[reg] = value
        return value

    def write_reg(self, reg: Reg, value: int):
        self.REGS_VALUE[reg] = value
        write_mem.write_reg(reg, value)

    def wait_for_reg_change(self, reg: Reg):
        previous_value = self.REGS_VALUE[reg]
        while True:
            value = self.read_reg(reg)
            if value != previous_value:
                logging.debug(f"reg {reg:x}: {previous_value:x} => {value:x}")
                break
            else:
                time.sleep(0.001)
        return value

    def wait_for_stop(self):
        logging.debug("wait for stop")
        self.wait_for_reg_change(Reg.PING)

    def send_command(self, command: Cmd, args, has_result = True):
        """Send command and wait for ack"""

        if len(args) == 2:
            self.write_reg(Reg.ARG1, args[0])
            self.write_reg(Reg.ARG2, args[1])
        elif len(args) == 1:
            self.write_reg(Reg.ARG1, args[0])
        elif len(args) != 0:
            assert False

        self.write_reg(Reg.CMD, command)

        self.wait_for_reg_change(Reg.PING)

        if has_result:
            return self.read_reg(Reg.OUT)

    def cmd_cont(self):
        logging.debug("CMD: continue")
        ping1 = self.REGS_VALUE[Reg.PING]
        self.send_command(Cmd.CONTINUE, [], has_result=False)
        ping2 = self.REGS_VALUE[Reg.PING]
        # If the hook is called again directly, the PING register might have
        # been incremented a second time, and the payload is ready to receive a
        # new command.
        if ping2 - ping1 > 1:
            # skip next wait_for_stop
            return True
        else:
            return False

    def cmd_disable_hook(self):
        """Disable the hook"""
        logging.debug("CMD: quit")
        self.send_command(Cmd.DISABLE_HOOK, [], has_result=False)

    def cmd_read_reg(self, n: int):
        logging.debug("CMD: read reg")
        value = self.send_command(Cmd.READ_REG, [n])
        logging.debug(f"reg {n}: {value:x}")
        return value

    def cmd_read_mem(self, addr: int, size: int):
        logging.debug("CMD: read mem")
        cmd = { 4: Cmd.READ_MEM4, 2: Cmd.READ_MEM2, 1: Cmd.READ_MEM1 }[size]
        value = self.send_command(cmd, [addr])
        logging.debug(f"addr {addr:x}: {value:x}")
        return value

    def cmd_write_mem(self, addr: int, value: int, size: int):
        logging.debug("CMD: write mem")
        cmd = { 4: Cmd.WRITE_MEM4, 2: Cmd.WRITE_MEM2, 1: Cmd.WRITE_MEM1 }[size]
        value = self.send_command(cmd, [addr, value], has_result=False)
        logging.debug(f"addr {addr:x}: {value:x}")

    def sigint_handler(self, sig, frame):
        logging.info("got KeyboardInterrupt")
        self.stop = True

    def run(self):
        signal.signal(signal.SIGINT, self.sigint_handler)

        skip_stop = False
        while True:
            if not skip_stop:
                self.wait_for_stop()
            #self.cmd_read_reg(4)
            #self.cmd_read_reg(32)
            if not self.stop:
                skip_stop = self.cmd_cont()
            else:
                self.cmd_disable_hook()
                break

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s.%(msecs)03d:%(name)s: %(message)s', datefmt='%H:%M:%S')

    d = Debugger()
    d.run()

    remove_hook()
