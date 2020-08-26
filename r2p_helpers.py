import r2pipe

#I copy-pasted this from stack overflow
#thanks Boaz Yaniv!
def decdec(inner_dec):
    def ddmain(outer_dec):
        def decwrapper(f):
            wrapped = inner_dec(outer_dec(f))
            def fwrapper(*args, **kwargs):
               return wrapped(*args, **kwargs)
            return fwrapper
        return decwrapper
    return ddmain



def must_have_r2pipe_arg(func):
    '''
    This decorator is ONLY to be used to wrap other r2pipe helper decorators.

    Check positional args to make sure that one of them is an r2pipe instance,
    then add the r2pipe instance to the front of the child function's argument
    list. Need this for the other wrappers since they use an r2pipe instance passed
    to the wrapped function.

    It was at this point that I realized that writing these little helper
    functions was probably more trouble than it was worth.
    '''
    def must_have_r2pipe_arg_wrapper(*args, **kwargs):

        #might have to account for other types
        r2pipe_types = [r2pipe.open_sync.open]

        r2pipe_arg = None
        for a in args:
            if type(a) in r2pipe_types:
                r2pipe_arg = a
                break

        if r2pipe_arg is None:
            print(args)
            raise Exception("A positional argument needs to be a\
            r2pipe instance to use this wrapper")

        else:
            func(r2pipe_arg, *args, **kwargs)

    return must_have_r2pipe_arg_wrapper

@decdec(must_have_r2pipe_arg)
def preserve_position(func):
    '''
    decorator that preserves the seek position before function calls.
    '''
    def preserve_pos_wrapper(r, *args, **kwargs):
        old_pos = int(r.cmd('s'), 16)
        func(*args, **kwargs)
        r.cmd('s {}'.format(old_pos))

    return preserve_pos_wrapper

@decdec(must_have_r2pipe_arg)
def preserve_esil_registers(func):
    '''
    decorator that preserves ESIL registers
    '''
    def preserve_er_wrapper(r, *args, **kwargs):
        old_aers = r.cmdj('aerj')
        #clear registers for enclosed function
        r.cmd('aer0')
        func(*args, **kwargs)
        for reg,val in old_aers.items():
            r.cmd('aer {}={}'.format(reg, val))
    return preserve_er_wrapper

@decdec(must_have_r2pipe_arg)
def preserve_flagspace(func):
    def preserve_fs_wrapper(r, *args, **kwargs):
        old_fs = r.cmdj('fssj')[-1]['name']
        func(*args, **kwargs)
        r.cmd('fs {}'.format(old_fs))
    return preserve_fs_wrapper

