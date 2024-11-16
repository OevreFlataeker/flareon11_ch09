"""
FlareOn 11 Challenge 9 solver.

Requires deobfuscated shellcode with stack unwinding instructions and CPU context saver invocation added.
"""

import capstone
import pefile
import traceback
import sys
from unicorn import *
from unicorn.x86_const import *
from capstone.x86 import *
from z3 import *

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True # Important! Otherwise we only have a subset of all the data we need to process

debug = False # Set to True for debug logging

# All kind of global vars
mul_locations = {} # "<sections>"->[rip, rip-ADDRESS, idx, value]
block_start = {}
lookup_ors = {} # "<sections>"-> [rip, rip-ADDRESS, block_cnt, or_result])
g_unique_byte_accesses = set()
results = {}
hooks={}

insn_cnt = 0
section = 0
monitored_values = []
monitored_lookup_values = [] 
post_step = False
post_monitor = None

ADDRESS=0x6660000
FLAG=0x783560
buf = None

lookup_cnt = 0
block_cnt = 0
monitored_op_dest = None
previous_mul_result = None
last_added = None

# Handle previous block arithmetics
tgt_is_last_added = None
src_is_current_mul_result = None
reset_previous_mul_result = False
reset_previous_op = None
got_first_shl = False
previous_shl_activities = []
g_new_input_byte = False
g_previous_new_input_address_ref = 0
transform_tracker = False
identified_transform = ''

# Ignore the following calls during processing
ignored_insn = [    
    UC_X86_INS_MOVHPS,    
    UC_X86_INS_CALL,
    UC_X86_INS_RET,
    UC_X86_INS_CLC,
]

# Register defines
register_map = {
    # 64-bit registers
    UC_X86_REG_RAX: 'rax',
    UC_X86_REG_RBX: 'rbx',
    UC_X86_REG_RCX: 'rcx',
    UC_X86_REG_RDX: 'rdx',
    UC_X86_REG_RSI: 'rsi',
    UC_X86_REG_RDI: 'rdi',
    UC_X86_REG_RBP: 'rbp',
    UC_X86_REG_RSP: 'rsp',
    UC_X86_REG_R8: 'r8',
    UC_X86_REG_R9: 'r9',
    UC_X86_REG_R10: 'r10',
    UC_X86_REG_R11: 'r11',
    UC_X86_REG_R12: 'r12',
    UC_X86_REG_R13: 'r13',
    UC_X86_REG_R14: 'r14',
    UC_X86_REG_R15: 'r15',

    # 32-bit registers
    UC_X86_REG_EAX: 'eax',
    UC_X86_REG_EBX: 'ebx',
    UC_X86_REG_ECX: 'ecx',
    UC_X86_REG_EDX: 'edx',
    UC_X86_REG_ESI: 'esi',
    UC_X86_REG_EDI: 'edi',
    UC_X86_REG_EBP: 'ebp',
    UC_X86_REG_ESP: 'esp',

    # 16-bit registers
    UC_X86_REG_AX: 'ax',
    UC_X86_REG_BX: 'bx',
    UC_X86_REG_CX: 'cx',
    UC_X86_REG_DX: 'dx',
    UC_X86_REG_SI: 'si',
    UC_X86_REG_DI: 'di',
    UC_X86_REG_BP: 'bp',
    UC_X86_REG_SP: 'sp',

    # 8-bit registers
    UC_X86_REG_AL: 'al',
    UC_X86_REG_AH: 'ah',
    UC_X86_REG_BL: 'bl',
    UC_X86_REG_BH: 'bh',
    UC_X86_REG_CL: 'cl',
    UC_X86_REG_CH: 'ch',
    UC_X86_REG_DL: 'dl',
    UC_X86_REG_DH: 'dh',
    UC_X86_REG_SIL: 'sil',
    UC_X86_REG_DIL: 'dil',
    UC_X86_REG_BPL: 'bpl',
    UC_X86_REG_R11B: 'r11b',
    UC_X86_REG_R12B: 'r12b',
    UC_X86_REG_R13B: 'r13b',
    UC_X86_REG_R10B: 'r10b',
    UC_X86_REG_R8B: 'r8b',
    UC_X86_REG_R15B: 'r15b',
    UC_X86_REG_R11D: 'r11d',
    UC_X86_REG_R15D: 'r15d',
    UC_X86_REG_R8D: 'r8d',
    UC_X86_REG_R14B: 'r14b',
    UC_X86_REG_R10D: 'r10d',
    UC_X86_REG_R13D: 'r13d',
    UC_X86_REG_R12D: 'r12d',
}

full_size_regs = {
    'cl': UC_X86_REG_RCX,
    'dl': UC_X86_REG_RDX,
    'al': UC_X86_REG_RAX,
    'bl': UC_X86_REG_RBX,
    'r8d': UC_X86_REG_R8,
    'r15b': UC_X86_REG_R15,
    'r9b': UC_X86_REG_R9,
    'r13b': UC_X86_REG_R13,
    'r11d': UC_X86_REG_R11,
    'r11b': UC_X86_REG_R11,
    'r14d': UC_X86_REG_R14,
    'r12d': UC_X86_REG_R12,
    'r9d': UC_X86_REG_R9,
    'r15d': UC_X86_REG_R15,
    'dil' : UC_X86_REG_RDI,
    'sil' : UC_X86_REG_RSI,    
    'bpl' : UC_X86_REG_RBP,
    'r12b' : UC_X86_REG_R12,
    'r14b' : UC_X86_REG_R14,
    'r10b' : UC_X86_REG_R10,
    'r10d' : UC_X86_REG_R10,
    'r13d' : UC_X86_REG_R13,
    'r8b' : UC_X86_REG_R8,
    'rdx' : UC_X86_REG_RDX,
    'rcx' : UC_X86_REG_RCX,
    'rsi' : UC_X86_REG_RSI,
    'rdi' : UC_X86_REG_RDI,
    'rax' : UC_X86_REG_RAX,
    'rbx' : UC_X86_REG_RBX,
    'rsp' : UC_X86_REG_RSP,
    'rbp' : UC_X86_REG_RBP,
    'r8' : UC_X86_REG_R8,
    'r9' : UC_X86_REG_R9,
    'r10' : UC_X86_REG_R10,
    'r11' : UC_X86_REG_R11,
    'r12' : UC_X86_REG_R12,
    'r13' : UC_X86_REG_R13,
    'r14' : UC_X86_REG_R14,
    'r15' : UC_X86_REG_R15,
    'eax' : UC_X86_REG_RAX,
    'ebx' : UC_X86_REG_RBX,
    'ecx' : UC_X86_REG_RCX,
    'edx' : UC_X86_REG_RDX,
    'esi' : UC_X86_REG_RSI,
    'edi' : UC_X86_REG_RDI,
    'ebp' : UC_X86_REG_RBP,
    'esp' : UC_X86_REG_RSP,
}

# Start/End of all sections, and the test register
# Values be replaced/corrected at runtime!
sections = [[0x00000, 0x00B4BF, 'r14'],  # 0  # end = 0xb4bc
            #[0x009384, 0x012A74, 'rbx'],  # 1
            [0x00B4D5, 0x0169C6, 'rbx'],  # 1
            #[0x012A8C, 0x01C4FC, 'r12'],
            [0x0169DB, 0x02235E, 'r12'],
            [0x01C515, 0x025105, 'rsi'],
            [0x02511E, 0x02D7B3, 'r15'],  # 4
            [0x02D7CC, 0x0368BA, 'r14'],
            [0x0368D2, 0x03FF8A, 'r15'],
            [0x03FFA2, 0x049192, 'rdi'],
            [0x0491AB, 0x052E1C, 'r13'],  # 8
            [0x052E35, 0x05C348, 'rbx'],
            [0x05C361, 0x06597B, 'rdi'],
            [0x065994, 0x06EBF1, 'rbx'],
            [0x06EC0A, 0x077C7B, 'r14'],  # 12
            [0x077C93, 0x081252, 'rdi'],
            [0x08126B, 0x08B9E5, 'r14'],
            [0x08B9FE, 0x09541F, 'r15'],
            [0x095437, 0x09F695, 'r13'],  # 16
            [0x09F6AE, 0x0A7F20, 'r12'],
            [0x0A7F38, 0x0B1012, 'r12'],
            [0x0B102A, 0x0BAF26, 'r12'],
            [0x0BAF3F, 0x0C44FD, 'rbp'],  # 20
            [0x0C4516, 0x0CE17A, 'r13'],
            [0x0CE193, 0x0D6E7F, 'rbp'],
            [0x0D6E98, 0x0DEF59, 'rbp'],
            [0x0DEF71, 0x0E7314, 'r13'],  # 24
            [0x0E732D, 0x0F00D4, 'rbx'],
            [0x0F00ED, 0x0F84DD, 'rbp'],
            [0x0F84F5, 0x10185F, 'rbp'],
            [0x101877, 0x10B58C, 'r12'],  # 28
            [0x10B5A5, 0x114DB2, 'rsi'],
            [0x114DCA, 0x11E1B3, 'rbx'],
            [0x11E1CB, 0x127931, 'rbx']] 

# Some helper functions for registers
def get_register_name_by_id(reg_id):
    return register_map[reg_id]

def get_full_size_reg_name(small):
    return full_size_regs[small]

def print_regs(uc):
    """
    Used for debugging purposes
    """
    registers = {
        'RAX': uc.reg_read(UC_X86_REG_RAX),
        'RBX': uc.reg_read(UC_X86_REG_RBX),
        'RCX': uc.reg_read(UC_X86_REG_RCX),
        'RDX': uc.reg_read(UC_X86_REG_RDX),
        'RSI': uc.reg_read(UC_X86_REG_RSI),
        'RDI': uc.reg_read(UC_X86_REG_RDI),
        'RSP': uc.reg_read(UC_X86_REG_RSP),
        'RBP': uc.reg_read(UC_X86_REG_RBP),
        'RIP': uc.reg_read(UC_X86_REG_RIP),
        'R8':  uc.reg_read(UC_X86_REG_R8),
        'R9':  uc.reg_read(UC_X86_REG_R9),
        'R10': uc.reg_read(UC_X86_REG_R10),
        'R11': uc.reg_read(UC_X86_REG_R11),
        'R12': uc.reg_read(UC_X86_REG_R12),
        'R13': uc.reg_read(UC_X86_REG_R13),
        'R14': uc.reg_read(UC_X86_REG_R14),
        'R15': uc.reg_read(UC_X86_REG_R15),
    }

    # Print the register values
    print("Register values:")
    for reg, value in registers.items():
        print(f"{reg}: 0x{value:016x}")

def get_register_constant_by_name(reg_name):
    """
    Helper function to get the unicorn register constant by name
    """
    return register_map.get(reg_name.lower(), None)

# Helper functions for PE loading
def load_pe_to_unicorn(pe_path):
    """
    Properly loads a PE for processing with unicorn
    """
    # Load the PE file
    pe = pefile.PE(pe_path)

    # Initialize Unicorn
    uc = Uc(UC_ARCH_X86, UC_MODE_64)

    # Get the base address of the module
    image_base = pe.OPTIONAL_HEADER.ImageBase
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        
    # Get virtual alignment 
    memory_alignment = pe.OPTIONAL_HEADER.SectionAlignment

    # Load PE into emulator
    add_data_sections(uc, pe, image_base, memory_alignment)

        # Get lower bounds of allocated memory from emulator
    memory_base = get_memory_lower_bound(uc)

        # Get upper bounds of allocated memory from emulator
    memory_top = get_memory_upper_bound(uc, memory_alignment)
        
        # Get the stack base
    stack_base = memory_align(0x1000, memory_alignment)
        
        # Get the stack size
    
    stack_size = memory_align(0x5000, memory_alignment)
        
        # Adjust the stack base and size if needed
    if stack_base +  stack_size > memory_base and stack_base < memory_top:
        stack_base = memory_align(memory_top + 0x1000, memory_alignment)

    # Map the stack
    uc.mem_map(stack_base, stack_size)
    tmp_RSP = stack_base + stack_size // 2
    uc.reg_write(UC_X86_REG_RSP, tmp_RSP)
    uc.reg_write(UC_X86_REG_RBP, tmp_RSP)
        
    
    return (uc, tmp_RSP)

def get_memory_lower_bound(uc) -> int:
    """
    Returns the lower bound of the allocated memory.
    """
    memory_segments = list(uc.mem_regions())
    memory_segments.sort(key=lambda x: x[0])
    memory_base = 0
    if len(memory_segments) > 0:
        memory_base = memory_segments[0][0]
    return memory_base
    
def get_memory_upper_bound(uc, memory_alignment) -> int:
    """
    Returns the upper bound of the allocated memory.
    """
    memory_segments = list(uc.mem_regions())
    memory_segments.sort(key=lambda x: x[1], reverse=True)
    memory_top = 0
    if len(memory_segments) > 0:
        memory_top = memory_align(memory_segments[0][1], memory_alignment)
    return memory_top

def memory_align(address: int, memory_alignment: int) -> int:
    """
    Aligns the given address to the nearest multiple of alignment.
    """
    
    return ((address + memory_alignment - 1) // memory_alignment) * memory_alignment

def add_data_sections(uc,pe, image_base,memory_alignment) -> None:
    """
    Adds sections to emulator
    """
    # For each section in the PE file add it to the emulator
    for section in pe.sections:
        # Get the section data
        data = section.get_data()
        # Get the section size
        size = section.Misc_VirtualSize
        # Align the section size
        size_aligned = memory_align(size, memory_alignment)
        # Get the section address
        address = image_base + section.VirtualAddress
        permissions = 0
        # Check if the section is readable
        if section.Characteristics & 0x40000000:
            permissions |= UC_PROT_READ
        # Check if the section is writable
        if section.Characteristics & 0x80000000:
            permissions |= UC_PROT_WRITE
        # Check if the section is executable
        if section.Characteristics & 0x20000000:
            permissions |= UC_PROT_EXEC

        # Map the memory with the combined permissions
        # print(f"Mapping section {section.Name.decode()} at 0x{address:x} with size 0x{size_aligned:x} and permissions {permissions}")
        uc.mem_map(address, size_aligned, permissions)
        uc.mem_write(address, data)

    return 

# Misc
def print_binary_grouped(number):
    # Convert the number to binary and remove the '0b' prefix
    binary_representation = bin(number)[2:]

    # Pad the binary representation with leading zeros to make its length a multiple of 8
    #padded_binary = binary_representation.zfill(len(binary_representation) + (8 - len(binary_representation) % 8) % 8)
    padded_binary = binary_representation.zfill(32)

    # Group the binary digits in sets of 8
    grouped_binary = [padded_binary[i:i+8] for i in range(0, len(padded_binary), 8)]

    # Join the groups with a space and print
    return(' '.join(grouped_binary))

def generate_random_string(length=32):
    """
    Generate an ascii printable string of length N
    """
    import string
    import random
    # Define the character set: digits and letters (uppercase and lowercase)
    characters = string.ascii_letters + string.digits
    # Generate a random string of the specified length
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string

# Monitored values helper functions
def print_monitored():
    for v in monitored_values:
        print(f"0x{v:x}")

def print_monitored_lookup():
    for v in monitored_lookup_values:
        print(f"0x{v:x}")

def add_monitor_lookup(value):
    """
    Add a monitored value during lookup tracking
    """
    if debug: print(f"DEBUG: Added value to lookup monitor: 0x{value:x}")
    monitored_lookup_values.append(value)

def add_monitor(value):
    """
    Add a monitored value
    """
    if value>0xff and not value in monitored_values:
        if debug: print(f"DEBUG: Added value to monitor: 0x{value:x}")
        monitored_values.append(value)
        
def count_subsequence(lst, subseq):
    """
    Counts the occurence of subseq in lst
    """
    count = 0
    subseq_length = len(subseq)

    for i in range(len(lst) - subseq_length + 1):
        if lst[i:i + subseq_length] == subseq:
            count += 1

    return count

# Hooks
def hook_mem_access(uc, access, address, size, value, user_data):
    """
    Tries to detect when a input/flag character is accessed
    """

    global g_new_input_byte
    global g_new_input_address_ref
    global g_unique_byte_accesses

    if address in range(lpDestination,lpDestination+32): # Check if a read to flag bytes happened
        if access == UC_MEM_READ:
            # Access to our flag input bytes
            pc = uc.reg_read(UC_X86_REG_RIP)
            if pc not in g_unique_byte_accesses:
                g_new_input_byte=True                
                g_new_input_address_ref = address # We need to find the address from which this access happened!
                g_unique_byte_accesses.add(pc)
    
def hook_mul(uc, address, size, user_data):
    """
    Hook for mul operation identification
    """
    
    global insn_cnt
    global section
    global debug
    insn_cnt+=1

    rip = uc.reg_read(UC_X86_REG_RIP)
    instruction_bytes = uc.mem_read(address, size)
        
    for insn in md.disasm(instruction_bytes, address):
        if "mul" in insn.mnemonic:            

            if len(insn.operands) > 0:                
                c = -1
                for i in insn.operands:
                    c += 1
                    if i.type == X86_OP_REG:
                        if debug: print("\t\toperands[%u].type: REG = %s" %(c, insn.reg_name(i.value.reg)))
                    if i.type == X86_OP_IMM:
                        if debug: print("\t\toperands[%u].type: IMM = 0x%x" %(c, i.value.imm))                    
                    if i.type == X86_OP_MEM:
                        if debug: print("\t\toperands[%u].type: MEM" %c)
                        if i.value.mem.base != 0:
                            if debug: print("\t\t\toperands[%u].mem.base: REG = %s" \
                                %(c, insn.reg_name(i.value.mem.base)))
                            rax_before = uc.reg_read(UC_X86_REG_RAX)
                            idx = rax_before - 0x30
                            
                            value = int.from_bytes(uc.mem_read(uc.reg_read(i.value.mem.base),8), byteorder='little')                                            
                            if debug: print(f"\t\t\tinput position {idx} multiply with 0x{value:x}")

                            # Store in our table
                            try:
                                x = mul_locations[f"{section}"]
                            except:
                                mul_locations[f"{section}"] = []
                            mul_locations[f"{section}"].append([rip, rip-ADDRESS, idx, value])
                                                    
def hook_track(uc, address, size, user_data):   
    """
    The main code of our tracer.
    Tracks values throughout the code
    """
    global monitored_op_dest
    global monitored_op_dest_insn
    # Try to trace all usages of monitored values
    # if post_step = True, we have just monitored an operation which included a monitored value and we need to fetch the result
    # We can stop monitoring once we find the first or operation (start of lookup manipulation)
    global debug
    global previous_mul_result
    global tgt_is_last_added, src_is_current_mul_result
    global last_added
    global got_first_shl
    global previous_shl_activities
    global reset_previous_mul_result
    global reset_previous_op
    global g_new_input_byte
    global g_new_input_address_ref
    global g_previous_new_input_address_ref
    global block_cnt
    global insn_cnt
    
    global section
    global transform_tracker
    global identified_transform
    global results
    global has_errors
            
    # Detect block change
    if g_new_input_byte:
        offset = g_new_input_address_ref-lpDestination
        if debug: print(f"Found potential block change at 0x{address:x} by accessing NEW keybyte at flag offset {offset} !!! op_at: 0x{address:x}, reference: 0x{g_new_input_address_ref:x}")
        # Check if the two accesses are far enough from each other, 0x40 is arbitrary chosen value
        if abs(address-g_previous_new_input_address_ref)<0x40:
            if debug: print(f"New access at 0x{address:x} is too close to previous access (previous: 0x{g_previous_new_input_address_ref:x}, current: 0x{address:x}). Not considering a block change!")
        else: # We have a block change
            block_cnt+=1
            if debug: print(f"Confirmed block change, now in block {block_cnt}: accessing NEW keybyte at flag offset {offset} !!! op_at: 0x{address:x}, reference: 0x{g_new_input_address_ref:x}")
            
            ########
            if debug: print(f"================= Start new block {block_cnt} =================")
                # Finish the block and calculate the residual
            if block_cnt>1:                          
                #last_added = None
                if debug: print("Monitored lookup ops values:")
                if debug: print_monitored_lookup()
                if debug: print("Monitored values:")
                if debug: print_monitored()
                try:
                    last_added = monitored_lookup_values.pop() # Was monitored_values
                except: 
                    pass
                                                            
                # Determine previous block multiplication result
                muls = mul_locations[f"{section}"][block_cnt-1]
                # Recalculate previous mul result (index of flag char's value * const)
                # previous_result = (flag[muls[2]])*muls[3]
                if debug: print(f"Previous mul: 0x{previous_mul_result:x}")                

                lookup_op='NONE'
                for idx, item in enumerate(previous_shl_activities):
                    if item=='shl':
                        if debug: print(f"Got SHL op on idx {idx}")
                        # Check next op
                        next_op = previous_shl_activities[idx+1]
                        if next_op == 'sub':
                            lookup_op = 'SUB'
                            break
                        elif next_op == 'add':
                            lookup_op = 'ADD'
                            break
                        elif next_op in ['not','or']:
                            lookup_op = 'XOR'
                            break
                        else:
                            lookup_op = 'ERROR'
                            print("Next lookup up is neither SUB, ADD, NOT, OR")
                            exit(1)

                if debug: print(f"Determined lookup const as {lookup_op} using last_added_lookup=0x{last_added:x} and previous_mul_result=0x{previous_mul_result:x}")            
                if debug: print(f"Transform tracker returned: {identified_transform}")
                if lookup_op!=identified_transform:
                    if debug: print("!!! ERROR!!! Counted transform op != identifed transform op. Error abort.")
                    has_errors = True
                
                # Perform the lookup mangling
                if lookup_op=='ADD':
                    lookup_const = last_added - previous_mul_result  # When is previous_mul_result changed? 
                    if debug: print(f"lookup_const = last_added - previous_mul_result = 0x{last_added:x} - 0x{previous_mul_result:x} = 0x{lookup_const:x}")
                elif lookup_op=='SUB':
                    lookup_const = previous_mul_result - last_added
                    if debug: print(f"lookup_const = previous_mul_result - last_added = 0x{previous_mul_result:x} - 0x{last_added:x} = 0x{lookup_const:x}")
                elif lookup_op=='XOR':                    
                    lookup_const = last_added ^ previous_mul_result
                    if debug: print(f"lookup_const = last_added ^ previous_mul_result = 0x{last_added:x} ^ 0x{previous_mul_result:x} = 0x{lookup_const:x}")                    
                else: #if lookup_op=='NONE':
                    print("Error couldnt determine lookup op")
                    sys.exit(1)

                # Add results               
                if lookup_const < -1:
                    lookup_const = lookup_const & 0xffffffffffffffff
                lookup_const &= 0xffffffffff
                
                results[block_cnt-1] = [mul_locations[f"{section}"][block_cnt-2][3], reset_previous_op, lookup_const, lookup_op]
                entry = results[block_cnt-1]
                if debug: print(f"Block {block_cnt-1}: multiplication constant: 0x{entry[0]:x}, mangle_op: {entry[1]}, lookup_value: 0x{entry[2]:x}, lookup_op: {entry[3]}")
                
                monitored_values.clear()
                monitored_lookup_values.clear()
                previous_shl_activities.clear()
                got_first_shl = False
                reset_previous_op = None

                # Add the last value we need to calculte the lookup table value
                if not last_added == None:
                    if not last_added in monitored_lookup_values:
                        add_monitor(last_added)
                                
                # Keep previous_result as the last_added from the last block (maybe not needed)
                previous_mul_result = last_added
                transform_tracker = False
                identified_transform = ''
                add_monitor(last_added)

                if debug: print(f"#### Calculated lookup const for block {block_cnt-1} for char at pos {muls[2]} is 0x{lookup_const:x}")
                if debug: print(f"#### Last added stays at: 0x{last_added:x}")
                
        g_new_input_byte = False
        g_previous_new_input_address_ref = address
        g_new_input_address_ref = 0x0

    # Are we in op+1
    if monitored_op_dest:
        i = monitored_op_dest
        i_insn = monitored_op_dest_insn
        c = 0 # Just for lazy printing
        
        # Get the result based on the operation type        
        if i.type == X86_OP_REG:            
            # Check for monitored
            # Check for full size reg!
            new_value = uc.reg_read(get_full_size_reg_name(get_register_name_by_id(i.value.reg)))
            
            # Reset previous_mul_result of needed:
            if reset_previous_mul_result:
                previous_mul_result = new_value & 0xffffffffffffffff
                if debug: print(f"Debug: reset previous_mul_result to 0x{new_value:x} via {reset_previous_op}")

                # Reset flags
                reset_previous_mul_result = False
                
                tgt_is_last_added = False
                src_is_current_mul_result = False
            
           
            if new_value not in monitored_values:
                add_monitor(new_value)
                if debug: print(f"\t\t\t\t\tAdded new monitored value from destination: 0x{new_value:x}")

            if monitored_op_dest_insn in ['sub','add','or','not','xor']:
                add_monitor_lookup(new_value)
                if debug: print(f"\t\t\t\t\tAdded new lookup op monitored value!: 0x{new_value:x}")
            
        elif i.type == X86_OP_IMM:
            # An immediate can never be a monitored operand?
            if debug: print("\t\toperands[%u].type: IMM = 0x%x" %(c, i.value.imm))                    
            if debug: print("\t\t\tDefinitely ignore, imm are never operands to change!")
        elif i.type == X86_OP_MEM:
            if debug: print("\t\toperands[%u].type: MEM" %c)
              
            if i.value.mem.index != 0:
                print("\t\t\toperands[%u].mem.index: REG = %s" \
                    %(c, insn.reg_name(i.value.mem.index)))
                print(f"No read impl: {i_insn} {i}")
                exit(1)                            

            # Size = bytes to read?
            if i.size!=8:
                print("Not size 8!")
                exit(1)

            # Check if i.value.imm maybe is the dereferenced value
            mem_addr = 0
            if i.value.mem.base!=0:
                mem_addr += uc.reg_read(i.value.mem.base)
            if i.value.mem.disp!=0:
                mem_addr += i.value.mem.disp
            new_value = int.from_bytes(uc.mem_read(mem_addr, i.size), byteorder='little')
            
            # Reset previous_mul_result of needed
            if reset_previous_mul_result:
                previous_mul_result = new_value  # Does it always trigger?
                # Reset flags
                tgt_is_last_added = False
                src_is_current_mul_result = False

            if not new_value in monitored_values:
                add_monitor(new_value)
                if debug: print(f"\t\t\t\t\tAdded new monitored value from destination (2): 0x{new_value:x}")
            if (not new_value in monitored_lookup_values) and (monitored_op_dest_insn in ['sub','add','or','not','xor']):
                add_monitor_lookup(new_value)
                if debug: print(f"\t\t\t\t\tAdded new lookup op monitored value from '{monitored_op_dest_insn}'!: 0x{new_value:x}")
                        
        # Clear the monitored state again    
        monitored_op_dest = None 
        monitored_op_dest_insn = None

    insn_cnt+=1
    flag = user_data 
    rip = uc.reg_read(UC_X86_REG_RIP)
    instruction_bytes = uc.mem_read(address, size)

    # Walk all insn of the current RIP
    for insn in md.disasm(instruction_bytes, address):
        
        if debug: print(f"Preparsing: 0x{rip:x},+0x{(rip-ADDRESS):x},{insn_cnt}: {insn.mnemonic} {insn.op_str}") 
        
        # We skip these right away, as they will never lead to a monitored value change
        if insn.id in ignored_insn or ('movzx' in insn.mnemonic) or ('push' in insn.mnemonic) or ('pop' in insn.mnemonic):            
            if debug: print(".")
            continue
    
        # 'not' will always lead to monitored value if register is a monitored value
        if 'not' in insn.mnemonic:
            operand = insn.operands[0]
            value = uc.reg_read(operand.value.reg)
            if value in monitored_values:                    
                    needs_monitoring=True

        # Check if we arrived at the final test value                    
        if "test" in insn.mnemonic:
            if debug: print(f"Final test at 0x{rip:x}")
            
            i = insn.operands[0]
            
            if i.type == X86_OP_REG:
                full_reg = i.value.reg
                value = uc.reg_read(full_reg)
                if debug: print(f"Test resolves to 0x{value:x}") 
                if value != 0:
                    # Adapt final test value - we want it to become 0
                    corrected_value = (results[9][1]-value) & 0xffffffffffffffff
                    if debug: print(f"Corrected final test val: 0x{corrected_value:x}")
                    results[9][1] = corrected_value
                    block_cnt=1

        # Check if we have a mul (kickoff op for tracking) (This is a special handling case)
        if "mul" in insn.mnemonic:
            previous_result = None
            got_first_shl = False
                        
            rax_before = uc.reg_read(UC_X86_REG_RAX)            
            
            # Read the constant from operand 0 referenced by a "qword ptr [<reg>]"
            operand = insn.operands[0]
            
            value = int.from_bytes(uc.mem_read(uc.reg_read(operand.value.mem.base),operand.size), byteorder='little')    
            product = (rax_before * value) & 0xffffffffffffffff

            if not product in monitored_values:
                add_monitor(product)
                if debug: print(f"\t\t\t\t\tAdded new product value to monitor (0x{product:x})")

            previous_mul_result = product

            if debug: print(f"0x{rip:x},+0x{(rip-ADDRESS):x},{insn_cnt}: {insn.mnemonic} {insn.op_str}")
            if debug: print(f"\t\t\t\t\tAdded result of mul operation (flag with constant): 0x{rax_before:x} * 0x{value:x} => 0x{product:x}")
            
            if block_cnt==8:
                if debug: print(f"We're in final block 8. Looking for last lookup transformation")
                if debug: print("Tracking next lookup ops sequences.")
                # As an exception we do not do post processing here as we exactly already know what to do and calced it already
            
            transform_tracker=True
            continue

        # Exclude standard MOVes if we operate on the full register
        if 'mov' in insn.mnemonic and insn.operands[0].size == 8:
            continue
                
        needs_monitoring = False
        tgtSetNow = False
        srcSetNow = False
        src_value = 0
        tgt_value = 0

        # Detect tracking changes in the operands
        for c in range(len(insn.operands)):
            # Walk (0 == dst and 1 == src operand)
            i = insn.operands[c]
            if i.type == X86_OP_REG:
                if debug: print("\t\toperands[%u].type: REG = %s" %(c, insn.reg_name(i.value.reg)))
                
                # Check if operand contains monitored value
                if insn.operands[0].size<8 and insn.operands[1].size<=insn.operands[0].size:
                    # Check the full register for a monitored value!
                    full_reg = get_full_size_reg_name(insn.reg_name(i.value.reg))
                else:
                    full_reg = i.value.reg
                
                value = uc.reg_read(full_reg)

                if value in monitored_values:  
                    # Determine if we have the previous/current mangle case
                    # Check tgt register for result from last block
                    
                    if c==0 and value == last_added:
                        tgt_is_last_added=True
                        tgtSetNow = True
                        tgt_value = value
                    else:
                        if not tgtSetNow:
                            tgt_is_last_added=False                    

                    # Check src register for result from this blocks mul
                    if c==1 and value == previous_mul_result:
                        src_is_current_mul_result=True
                        srcSetNow = True                        
                        src_value = value
                    else:
                        if not srcSetNow:                         
                            src_is_current_mul_result=False
                    needs_monitoring=True
            elif i.type == X86_OP_IMM:
                # An immediate can never be a monitored operand?
                if debug: print("\t\toperands[%u].type: IMM = 0x%x" %(c, i.value.imm))                    
                if debug: print("\t\t\tDefinitely ignore, imm are never operands to change!")
            elif i.type == X86_OP_MEM:
                if debug: print("\t\toperands[%u].type: MEM" %c)

                if i.value.mem.base != 0:
                    if debug: print("\t\t\toperands[%u].mem.base: REG = %s" \
                        %(c, insn.reg_name(i.value.mem.base)))                    
                    
                if i.value.mem.index != 0:
                    if debug: print("\t\t\toperands[%u].mem.index: REG = %s" \
                        %(c, insn.reg_name(i.value.mem.index)))
                    print(f"No read impl: {insn.mnemonic} {insn.op_str}")
                    exit(1)
                if i.value.mem.disp != 0:
                    if debug: print("\t\t\toperands[%u].mem.disp: 0x%x" \
                        %(c, i.value.mem.disp))
                                  
                # Check if i.value.imm maybe is the dereferenced value
                mem_addr = 0
                if i.value.mem.base!=0:
                    mem_addr += uc.reg_read(i.value.mem.base)
                if i.value.mem.disp!=0:
                    mem_addr += i.value.mem.disp
                value = int.from_bytes(uc.mem_read(mem_addr, i.size), byteorder='little')
                
                # Buggy check of both operands resets the flag
                if value in monitored_values:
                    if c==0 and value == last_added:                    
                        tgt_is_last_added=True
                        tgtSetNow = True
                        tgt_value = value
                    else:
                        if not tgtSetNow:
                            tgt_is_last_added=False
                        
                    # Check src register for result from this blocks mul
                    if c==1 and value == previous_mul_result:                    
                        src_is_current_mul_result=True
                        src_value = value
                        srcSetNow = True
                    else:
                        if not srcSetNow:                         
                            src_is_current_mul_result=False

                    needs_monitoring=True     
        
        # Record lookup ops
        if got_first_shl==True and transform_tracker:
            if insn.mnemonic=='shl' or insn.mnemonic=='sub' or insn.mnemonic == 'not' or insn.mnemonic == 'or' or insn.mnemonic== 'add':
                previous_shl_activities.append(insn.mnemonic)
        
        # ... or start the recording?
        if insn.mnemonic=='shl' and got_first_shl==False and transform_tracker:           
            got_first_shl=True
            previous_shl_activities.clear()
            previous_shl_activities.append('shl')
            

        # Count transform ops
        if transform_tracker:
            xor_subsequence = ["shl", "not", "shl", "or"]
            add_subsequence = ["shl", "add"]
            sub_subsequence = ["shl", "sub"]

            # Count the occurrences
            occurences_xor = count_subsequence(previous_shl_activities, xor_subsequence)
            occurences_add = count_subsequence(previous_shl_activities, add_subsequence)
            occurences_sub = count_subsequence(previous_shl_activities, sub_subsequence)
            if occurences_xor >= 4:
                if debug: print("Identified XOR transform op!")
                identified_transform = 'XOR'
                transform_tracker = False                                                              
            elif occurences_add == 5:
                if debug: print("Identified ADD transform op!")
                identified_transform = 'ADD'
                transform_tracker = False
            elif occurences_sub == 5:
                if debug: print("Identified SUB transform op!")
                identified_transform = 'SUB'
                transform_tracker = False

        if identified_transform != '' and block_cnt == 8: # Should be generic if possible
            # Try to get the constant for the last one
            # Special handling of block 8 without any clear transition to block 9 so our usual code won't trigger. 
            
            if debug: print(f"================= Start new block {block_cnt} (custom)=================")            
        
            last_added = monitored_lookup_values.pop()
            muls = mul_locations[f"{section}"][block_cnt-1]
            block_cnt = 9

            if debug: print(f"Previous mul: 0x{previous_mul_result:x}")
            if debug: print(f"Transform tracker identified op as '{identified_transform}' using last_added_lookup=0x{last_added:x} and previous_mul_result=0x{previous_mul_result:x}")            

            lookup_op = identified_transform
            if lookup_op=='ADD':
                lookup_const = last_added - previous_mul_result  # When is previous_mul_result changed? 
                if debug: print(f"lookup_const = last_added - previous_mul_result = 0x{last_added:x} - 0x{previous_mul_result:x} = 0x{lookup_const:x}")
            elif lookup_op=='SUB':
                lookup_const = previous_mul_result - last_added
                if debug: print(f"lookup_const = previous_mul_result - last_added = 0x{previous_mul_result:x} - 0x{last_added:x} = 0x{lookup_const:x}")
            elif lookup_op=='XOR':                    
                lookup_const = last_added ^ previous_mul_result
                if debug: print(f"lookup_const = last_added ^ previous_mul_result = 0x{last_added:x} ^ 0x{previous_mul_result:x} = 0x{lookup_const:x}")
                
            else: #if lookup_op=='NONE':
                print("Error couldnt determine lookup op")
                exit(1)

            monitored_values.clear()    
            monitored_lookup_values.clear()
            previous_shl_activities.clear()
            got_first_shl = False
            identified_transform = ''
            
            # Add the last value we need to calcaulte the lookup table value
            if not last_added == None:
                if not last_added in monitored_lookup_values:
                    add_monitor(last_added)
            
            if lookup_const < -1:
                lookup_const = lookup_const & 0xffffffffffffffff
            lookup_const &= 0xffffffffff
            
            results[block_cnt-1] = [mul_locations[f"{section}"][block_cnt-2][3], reset_previous_op, lookup_const, lookup_op]
            entry = results[block_cnt-1]
            if debug: print(f"Block {block_cnt-1}: multiplication constant: 0x{entry[0]:x}, mangle_op: {entry[1]}, lookup_value: 0x{entry[2]:x}, lookup_op: {entry[3]}")
                
            previous_mul_result = last_added
            add_monitor(last_added)
            if debug: print(f"#### Calculated lookup const for block {block_cnt-1} for char at pos {muls[2]} is 0x{lookup_const:x}")
            if debug: print(f"#### Last added stays at: 0x{last_added:x}")

            if block_cnt==9:
                if debug: print(f"#### Final const to reach 0 is last_added: 0x{last_added:x}")
                if debug: print("Done with block")
                results[block_cnt]=[None,last_added,None,None]              
            
        if needs_monitoring:
            # We need to get the result before the parsing of the next opcode!
            if debug: print(f"0x{rip:x},+0x{(rip-ADDRESS):x},{insn_cnt}: {insn.mnemonic} {insn.op_str}")
            monitored_op_dest = insn.operands[0] # Get handle to the destination operand
            monitored_op_dest_insn = insn.mnemonic # Track if its lookup ops

            # Determine if insn.operands[0] holds the "last_added" and insn.operands[1]=the current mul result, in this case we need to set the flag that in the next step 
            # previous_mul_result needs to be set to the value of the operation in order to cope with the arithmetics in each block
            if tgt_is_last_added and src_is_current_mul_result and tgtSetNow and srcSetNow:
                reset_previous_mul_result=True
                reset_previous_op = insn.mnemonic.upper()
                if debug: print(f"Debug: reset_previous_mul_result: tgt=0x{tgt_value:x}, src=0x{src_value:x} via {reset_previous_op}")
            else:
                reset_previous_mul_result=False

# The main subs                          
def find_muls(section=0):
    """
    Populates the mul table with the RVA/details of all mul operations in the shellcode
    """    
    SEC_START = 0
    SEC_END = 1
    insn_cnt = 0
    flag=b'0123456789:;<=>?@ABCDEFGHIJKLMNO' # Needed to get proper position
    mu.mem_write(lpDestination, bytes(flag))
    mu.reg_write(UC_X86_REG_RCX, lpDestination)
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RBP, rsp)    
    hook_id = mu.hook_add(UC_HOOK_CODE, hook_mul, None, ADDRESS+sections[section][SEC_START], ADDRESS+sections[section][SEC_END])
    hooks["HOOK_MUL"] = hook_id
    mu.emu_start(ADDRESS+sections[section][SEC_START], ADDRESS + sections[section][SEC_END])

def track(section, rsp):
    """
    The main routine to track the values through the shellcode
    """
    global block_cnt
    global results
    global monitored_values
    global monitored_lookup_values
    global g_unique_byte_accesses
    global has_errors
    global equations
    has_errors = False
    g_unique_byte_accesses= set()
    flag = b''
    SEC_START = 0
    SEC_END = 1
    insn_cnt = 0
    flag=b'0123456789:;<=>?@ABCDEFGHIJKLMNO' # Needed to get proper position
    #flag=b'ABCDEFGHIJKLMNOPQRSTUVWXZY012345'    
    #flag=b'e343D$dhwi23nsdinnwIDh2312fejw_e'    
    
    mu.emu_stop()
    mu.mem_write(lpDestination, bytes(flag))
    mu.reg_write(UC_X86_REG_RCX, lpDestination)
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RBP, rsp)
    try:
        mu.hook_del(hooks["HOOK_MUL"])             
    except:
        pass
    
    hook_id = mu.hook_add(UC_HOOK_CODE, hook_track, flag, ADDRESS+sections[section][SEC_START], ADDRESS+sections[section][SEC_END])
    hooks["HOOK_TRACE"] = hook_id
    hook_id = mu.hook_add(UC_HOOK_MEM_READ, hook_mem_access)
    hooks["HOOK_MEM_READ"] = hook_id
    print(f"Trace start at 0x{ADDRESS+sections[section][SEC_START]:x}")
    results = {}
    monitored_values = []
    monitored_lookup_values = []

    # Kick off unicorn
    mu.emu_start(ADDRESS+sections[section][SEC_START], ADDRESS + sections[section][SEC_END])

    # We're done (emulation is finished)
    print(f"Section: {section+1}, Start: 0x{(ADDRESS+sections[section][SEC_START]):x}, End: 0x{(ADDRESS + sections[section][SEC_END]):x}")
    equation = ''
    
    for i in range(1,9):
        entry = results[i]
        print(f"Block {i}: multiplication constant: 0x{entry[0]:x}, mangle_op: {entry[1]}, lookup_value: 0x{entry[2]:x}, lookup_op: {entry[3]}")
        muls = mul_locations[f"{section}"][i-1]
        
        # Auto-generate the Z3 equations
        if entry[1] == None:
            equation = f'(ZeroExt(24, input_flag[{muls[2]}]) * 0x{entry[0]:x})'
        elif entry[1] == 'ADD':
            equation = '(' + equation + f' + (ZeroExt(24, input_flag[{muls[2]}]) * 0x{entry[0]:x}))'
        elif entry[1] == 'SUB':
            equation = '(' + equation + f' - (ZeroExt(24, input_flag[{muls[2]}]) * 0x{entry[0]:x}))'
        elif entry[1] == 'XOR':
            equation = '(' + equation + f' ^ (ZeroExt(24, input_flag[{muls[2]}]) * 0x{entry[0]:x}))'
        if entry[3] == 'ADD':
            equation = f'({equation} + 0x{entry[2]:x})'
        elif entry[3] == 'SUB':
            equation = f'({equation} - 0x{entry[2]:x})'
        elif entry[3] == 'XOR':
            equation = f'({equation} ^ 0x{entry[2]:x})'
        if entry[2]<0x1000:
            print(f"\t\t\tSomething fishy wthe last lookup value")

    # Add the final equation
    print(f"Block 9: Final manipulation: SUB 0x{(results[9][1]):x}")
    equation = f'({equation} - 0x{(results[9][1]):x}) == 0'
    equations.append(equation)
    print(equation)
    block_cnt = 0

    # Deactivate the hooks
    try:
        mu.hook_del(hooks["HOOK_TRACE"])             
    except:
        pass
    try:
        mu.hook_del(hooks["HOOK_MEM_READ"])             
    except:
        pass

def populate_sections():
    """
    Populates the section table with start/end offset from the shellcode
    """
    global sections
    linenumber = 1
    jmps_found = 0
    got_jmp = False

    end_current = 0x0
    test_current = 0x0
    start_next = 0x0
    sections.clear()
    # Find the jmp/test opcodes in the deadlisting
    with open("serpentine_deadlisting.txt","r") as f:        
        l = f.readline().strip()
        while l:
            if got_jmp:
                #print(f"{linenumber}: {l} # Start of section {jmps_found+1}")
                start_next = int(l.split(':')[0],16)-0x1000
                got_jmp = False
            if "test" in l:
                #print(f"{linenumber}: {l} # test {jmps_found}")
                test_current = int(l.split(':')[0],16)-0x1000
                print(f"Section {jmps_found}: start=0x{start_next:x}, test=0x{test_current:x}")
                
            if "jmp" in l:
                got_jmp = True
                jmps_found += 1
                #print(f"{linenumber}: {l} # jmp {jmps_found}")        
                end_current = int(l.split(':')[0],16)-0x1000
                sections.append([start_next, end_current]) # Important we need the final address! Otherwise the "test" insns will not be executed and the final correction will be wrong

                
            linenumber+=1    
            l = f.readline().strip()
    print(sections)

# Main loop    
try:
    # Read our shellcode
    with open("final_shell.bin", "rb") as f:
        buf = f.read()

    # Read the PE
    mu, rsp = load_pe_to_unicorn("patched.exe")

    ori_rsp = rsp

    # Allocate some memory and write our shellcode to it
    mu.mem_map(ADDRESS, 16 * 1024 * 1024)
    mu.mem_write(ADDRESS, buf)
    
    # Prep the exectution
    lpAddress = 0x14089B8E0
    mu.mem_write(lpAddress, b'\x00\x00\x66\x06')
    lpDestination = 0x14089B8E8
        
    # Populate section dict
    populate_sections()
    
    equations = []

    # Process all 32 sections
    for sec in range(0,32):
        
        section = sec

        # First find the mul in the section
        find_muls(section)
        
        # Then track the value through the code until the first lookup
        print(f'Starting analysis for section {section} at 0x{sections[section][0]:x}')
        try:
            track(section, rsp)
        except Exception as e:
            print(f"Track returned errror: {e}")
            print(traceback.print_exc())
        reset_previous_op = None
        
    print(f'Found {len(equations)} correct equations for z3')
    print(equations)
    
    # Z3 auto-solve with everything we found out
    
    input_flag = [BitVec(f'c{i}', 8) for i in range(32)]
    solver = Solver()
    for char in input_flag:
        solver.add(char >= 32)
        solver.add(char <= 126)
    
    for index in [0,4,8,12,16,20,24,28,
                  1,5,9,13,17,21,25,29,
                  2,6,10,14,18,26,30,
                  7,11,15,19,23,27,31
                  ]:
        solver.add(eval(equations[index]))
        
    if solver.check() == sat:
        model = solver.model()

        # Convert the solution into a string
        result = ''.join(chr(model[char].as_long()) for char in input_flag)
        print("\n\nSolution found:", result)
        print(f"Hex-ASCII: 0x{result.encode('latin-1').hex()}")
    else:
        print("No solution exists.")

except Exception as e:
    print(f"Error: {e}")
    traceback.print_exc()
