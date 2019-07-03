#don't need to import r2pipe b/c running from
#radare
r = r2pipe.open()

#get functions
funs = r.cmdj('aflj')

funclist = []

for fun in funs:
    addr = fun['offset']
    name = fun['name']
    xrefs = len(fun.get('codexrefs', []))
    funclist.append((addr, name, xrefs))

funclist.sort(key=lambda x: x[2], reverse=True)

for f in funclist:
    print("{}\t{}\t{}".format(*f))


