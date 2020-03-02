import r2pipe

r = r2pipe.open()
#push old flagspace setting, set to 'all'
r.cmd('fs+*')

#set scr.color=0 as workaround for json output bug
#save old scr.color
osc = r.cmd('e scr.color')
try:
    osc = int(osc)
except:
    #safe default I guess
    osc = 0
r.cmd('e scr.color=0')

#hello, my name is haystack and I program in list comprehensions because I was
#brain damaged by Lisp and Haskell at a young age.

#get list of flags generated by aav
#after doing this I realized I could have used `fj`. whoops.
aavs = [x.split(' ') for x in r.cmd('f~aav').split('\n') if len(x) > 0]

#location, length, flag_name
aavs = [(int(x[0], 16), int(x[1]), x[2]) for x in aavs]

#filter for odd values (function pointer is really to loc - 1, but thumb)
aavs = [x for x in aavs if x[0] % 2 == 1]

#filter for addresses where x-1 is a push instruction (function prologue)
aavs = [x for x in aavs if 'push' in r.cmd('pd 1 @ {}'.format(x[0]-1))]

#filter for addresses where anal didn't already find function there
aavs = [x for x in aavs if len(r.cmd('f~fcn.{:08x}'.format(x[0]-1))) == 0]

for aav in aavs:
    #create function
    r.cmd('af @ {}'.format(aav[0] - 1))
    #remove aav flag
    r.cmd('f-{}'.format(aav[2]))
    #create new aav flag (not sure if necessary)
    r.cmd('f+aav.0x{:08x} {} {}'.format(aav[0]-1, aav[1], aav[0]-1))
    #recreate crossrefs
    #save crossrefs to address
    xrefs = r.cmdj('axtj {}'.format(aav[0]))
    if xrefs is None:
        #nothing to do here
        continue
    else:
        #delete crossrefs to address
        r.cmd('ax- {}'.format(aav[0]))
        #recreate crossrefs at correct address
        for xref in xrefs:
            r.cmd('ax {} {}'.format(aav[0]-1, xref['from']))


#return flagspaces to their former state
r.cmd('fs-')

#set scr.color to old value
r.cmd('e scr.color={}'.format(osc))

