import r2pipe
from r2p_helpers import preserve_esil_registers,\
                        preserve_flagspace,\
                        preserve_position

@preserve_esil_registers
@preserve_flagspace
@preserve_position
def rename_stubs(r, f):
    '''
    calculate proper function name for reloc stub.

    Arguments:
      r: r2pipe() object
      f: json representation of function (from aflj)
    '''

    #if name starts with 'sym.imp' it's already been named
    if f['name'].startswith('sym.imp'):
        return

    #setup analysis
    r.cmd('s {}'.format(f['offset']))
    #setup ESIL
    r.cmd('aeip; aeim')

    #execute until final instruction
    while True:#lol
        current_instr = r.cmdj('pdj1 @ pc')[0]
        #I used to check if offset = fcn_last but aav flags fuck that up
        if current_instr["opcode"].startswith('ldr pc'):
            break
        else:
            r.cmd('aes')

    #exploit the format of the ESIL. Probably only works for ARM
    got_offset = int(r.cmdj('pdj1 @ pc')[0]['esil'].split(",")[0])
    ip = r.cmdj('aerj')['ip']
    reloc_addr = got_offset + ip
    r.cmd('fs relocs')

    flag = [f for f in r.cmdj('fj') if f['offset'] == reloc_addr]
    if len(flag) < 1:
        print("no reloc found @ {} in function {}".format(hex(reloc_addr), f['name']))
    else:
        fname = flag[0]['name'][6:]
        r.cmd('afn sym.imp.{}'.format(fname))








r = r2pipe.open()

############################
#get bounds of .plt section#
############################

sections = r.cmdj('iSj')

#find section named '.plt'.
#assume there's only one
plts = [s for s in sections if s['name']=='.plt']
if len(plts) < 1:
    print('no .plt section found.')
    exit()
else:
    plt = plts[0]
    plt_start = plt['vaddr']
    plt_size = plt['vsize']
    plt_end = plt_start + plt_size

#get list of functions
all_functions = r.cmdj('aflj')

#use f['offset'] > plt_start instead of f['offset'] >=plt_start
#to exclude the resolver function at the top of .plt
plt_stubs = [f for f in all_functions if f['offset'] > plt_start\
             and f['offset'] < plt_end]

for stub in plt_stubs:
    rename_stubs(r, stub)
