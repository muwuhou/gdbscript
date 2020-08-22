
PYOBJECT_PTR = gdb.lookup_type("PyObject").pointer()
PYOBJECT_PTR2 = PYOBJECT_PTR.pointer()
PYVAROBJECT_PTR = gdb.lookup_type("PyVarObject").pointer()
PYLONGOBJECT_PTR = gdb.lookup_type("PyLongObject").pointer()
PYDICTOBJECT_PTR = gdb.lookup_type("PyDictObject").pointer()
PYDICTKEYENTRY_PTR = gdb.lookup_type("PyDictKeyEntry").pointer()
PYLISTOBJECT_PTR = gdb.lookup_type("PyListObject").pointer()
PYTUPLEOBJECT_PTR = gdb.lookup_type("PyTupleObject").pointer()
PYASCIIOBJECT_PTR = gdb.lookup_type("PyASCIIObject").pointer()
PYTYPEOBJECT_PTR = gdb.lookup_type("PyTypeObject").pointer()
PYFRAMEOBJECT_PTR = gdb.lookup_type("PyFrameObject").pointer()
PYCODEOBJECT_PTR = gdb.lookup_type("PyCodeObject").pointer()
PYMODULEOBJECT_PTR = gdb.lookup_type("PyModuleObject").pointer()
PYGENOBJECT_PTR = gdb.lookup_type("PyGenObject").pointer()
PYASYNCGENOBJECT_PTR = gdb.lookup_type("PyAsyncGenObject").pointer()
PYCOROOBJECT_PTR = gdb.lookup_type("PyCoroObject").pointer()
PYFUNCTIONOBJECT_PTR = gdb.lookup_type("PyFunctionObject").pointer()
PYMETHODOBJECT_PTR = gdb.lookup_type("PyMethodObject").pointer()

CHAR_PTR = gdb.lookup_type("char").pointer()
LONG_PTR = gdb.lookup_type("long").pointer()
PYTHREADSTATE_PTR = gdb.lookup_type("PyThreadState").pointer()
PYINTERPRETERSTATE_PTR = gdb.lookup_type("PyInterpreterState").pointer()
GC_HEAD_SIZE = gdb.lookup_type("PyGC_Head").sizeof  # gc head overhead, 24 bytes

# TODO: Traverse object so that objects that's not tracked by GC can also be dumpped.
#       Python gcmodule.c use tp_traverse method registerd for each type to do such
#       traversal. We cannot use this approach here, but we may be able to probing
#       object by check if each field of an object and see if it is a PyObject* field.
def heap_dump(outfile=None):
    """ Python gc tracks objects that could form reference cycle.
        This normally include all objects except those 'atom' object such as int, long, str...
        Traverse the gc list to find all tracked objects (similar to python call gc.get_objects())

        :return  List of all object (addresses)
    """
    generations = gdb.parse_and_eval("generations")  # global gc root
    NUM_GEN = 3
    addresses = []

    for gen in range(NUM_GEN):
        ghead = generations[gen]["head"]
        g = ghead["gc"]["gc_next"].dereference()
        while g.address != ghead.address:
            addr = long(g.address) + GC_HEAD_SIZE
            addresses.append(addr)
            g = g["gc"]["gc_next"].dereference()
    print "there are %s total objects" % len(addresses)
    if outfile:
        bag = {}  # name -> (total_count, total_size)
        with open(outfile, "w") as fh:
            print "writing objdump to %s" % outfile
            fh.write("%-20s  %-5s  %-5s  %-5s\n" % ("address", "refcnt", "size", "type"))
            for addr in addresses:
                obj = PyObject(addr)
                typ = obj.type()
                fh.write("0x%-20x  %-5d  %-5d  %-5s\n" % (addr, obj.refcnt, typ.basicsize, typ.name))
                bag.setdefault(typ.name, (0, 0))
                cnt, sz = bag[typ.name]
                bag[typ.name] = (cnt+1, sz+typ.basicsize)
        with open(outfile + ".summary", "w") as fh:
            print "writing summary to %s.summary" % outfile
            fh.write("%-40s  %-10s  %-10s\n" % ("type", "total_sz", "total_cnt"))
            # sort by total_size in descending order
            for k in sorted(bag.keys(), key=lambda x:bag[x][1], reverse=True):
                fh.write("%-40s  %-10d  %-10d\n" % (k, bag[k][1], bag[k][0]))
    return addresses


class PyObject(object):
    ''' Represent PyObject* object '''
    def __init__(self, address):
        ''' address could be a gdb.Value or a integer representing memory address '''
        if type(address) is gdb.Value:
            self.val = address
        else:
            self.val = gdb.Value(address)
        self.val = self.val.cast(PYOBJECT_PTR)   # gdb.Value object
        self.address = long(self.val)
        self.refcnt = long(self.val["ob_refcnt"])

    @staticmethod
    def typename(address):
        ''' Given an address, find out its type name.
            Do not try to construct PyObject and PyTypeObject to avoid recrusion. (used by PyObj dispatcher).
        '''
        return gdb.Value(address).cast(PYOBJECT_PTR)["ob_type"]["tp_name"].string()

    def type(self):
        return PyTypeObject(self.val.cast(PYOBJECT_PTR)["ob_type"])

    def type_chain(self):
        ''' get the type chain (metaclass chain)'''
        chain = []
        tp = self.type()
        while True:
            chain.append(tp)
            tptp = tp.type()
            if tptp is tp:
                break
            tp = tptp
        return ' <- '.join(x.full_name for x in chain)

    def base_chain(self):
        ''' get the base chain (inheritance chain)'''
        return self.type().base_chain()

    def all_bases(self):
        return self.type().all_bases()

    def parent(self):
        return self.type().parent()

    def attrs(self):
        ''' return attributes defined in object __dict__ '''
        tp = self.type()
        attrs = {}
        if tp.dictoffset:
            d = gdb.Value(self.address + tp.dictoffset).cast(PYOBJECT_PTR2).dereference()
            if long(d):
                # __dict__ slot has a valid PyObject* pointer
                attrs = PyDictObject(d).dict
        return attrs

    def __str__(self):
        return "%s(0x%x)" % (self.type().name, self.address)

    def __repr__(self):
        return self.__str__()


class PyVarObject(PyObject):
    ''' Represent PyVarObject* object '''
    def __init__(self, address):
        ''' address could be a gdb.Value or a integer representing memory address '''
        if type(address) is gdb.Value:
            self.val = address
        else:
            self.val = gdb.Value(address)
        self.val = self.val.cast(PYVAROBJECT_PTR)    # gdb.Value object
        self.address = long(self.val)
        self.refcnt = long(self.val["ob_base"]["ob_refcnt"])
        self.ob_size = long(self.val["ob_size"])


class PyTypeObject(PyVarObject):
    ''' Represent struct _typeobject* object '''
    def __init__(self, address):
        super(PyTypeObject, self).__init__(address)
        self.val = self.val.cast(PYTYPEOBJECT_PTR)    # gdb.Value object
        self.address = long(self.val)
        self.name = self.val["tp_name"].string()
        # self.doc = self.val["tp_doc"].string()   # TODO: tp_doc can be nullptr
        self.basicsize = long(self.val["tp_basicsize"])
        self.dictoffset = long(self.val["tp_dictoffset"])
        self.weaklistoffset = long(self.val["tp_weaklistoffset"])
        self.base = long(self.val["tp_base"])
        self.bases = long(self.val["tp_bases"])
        self.mro = long(self.val["tp_mro"])
        self.tp_dict = PyDictObject(self.val["tp_dict"], shallow=True).str_dict()
        self.module = self.tp_dict.get('__module__', '')
        if type(self.module) not in (str, unicode):
            self.module = ''
        self.full_name = '%s.%s' % (self.module, self.name) if self.module else self.name

    def type(self):
        val = self.val.cast(PYTYPEOBJECT_PTR)
        _type = val["ob_base"]["ob_base"]["ob_type"]
        # Get the address of the ptr and compare them
        if long(_type) == long(val):
            # The type of the type object is itself
            return self
        return PyTypeObject(_type)

    def parent(self):
        ''' parent class '''
        return PyTypeObject(self.base)

    def base_chain(self):
        ''' inheritance chain. Note this different from type_chain which is about metaclass '''
        base = self
        chain = []
        while True:
            chain.append(base)
            basebase = base.base
            if basebase == 0:
                break
            base = PyTypeObject(basebase)
        return ' <= '.join(x.full_name for x in chain)

    def all_bases(self):
        ''' get all bases (including itself). Deals with multiple inheritance '''
        import collections
        bases = collections.OrderedDict()
        # Do a BFS on the inheritance tree, result is saved in ordered dict.
        q = collections.deque()
        q.append(self)
        while q:
            x = q.popleft()
            if x.full_name not in bases:
                bases[x.full_name] = x
            for p in PyTupleObject(x.bases, shallow=True).tuple:
                q.append(PyTypeObject(p.address))
        return bases.keys()


    def __str__(self):
        return "type<%s>(%s, size=%d, dictoffset=%d, weakoffset=%d, base=0x%x, bases=0x%x, mro=0x%x, tp_dict=%s)" % (
                self.name, self.full_name, self.basicsize, self.dictoffset, self.weaklistoffset, self.base, self.bases, self.mro, self.tp_dict)


# There're 3 types of strings: PyASCIIObject, PyCompactUnicodeObject, PyUnicodeObject
# They all have PyASCIIObject header. Its state.compact, self.ascii, self.compact flag
# can be used to distinguish the type.
class PyASCIIObject(PyObject):
    def __init__(self, address):
        super(PyASCIIObject, self).__init__(address)
        self.val = self.val.cast(PYASCIIOBJECT_PTR)
        self.ascii = bool(self.val["state"]["ascii"])
        self.compact = bool(self.val["state"]["compact"])
        self.kind = int(self.val["state"]["kind"])
        self.length = long(self.val["length"])
        self.hash = long(self.val["hash"])
        if self.ascii and self.compact:
            self.buf = self.val[1].address.cast(CHAR_PTR).string() # char buffer is after the object
            #assert len(self.buf) == self.length # TODO: .string() call should pass in self.length in previous line

    def __str__(self):
        return '"%s"' % self.buf


class PyDictObject(PyObject):
    ''' Represent PyDictObject* object'''

    def __init__(self, address, created={}, shallow=False):
        super(PyDictObject, self).__init__(address)
        self.val = self.val.cast(PYDICTOBJECT_PTR)
        # Decode dict object: see python source: dict_keys(), dict_values() for data structure.
        ma_used = long(self.val["ma_used"])
        ma_keys = self.val["ma_keys"]
        ma_values = self.val["ma_values"]
        self.splitted = long(ma_values) != 0   # if ma_values field != NULL, then splitted mode
        dk_nentries = long(ma_keys["dk_nentries"])
        dk_entries = self._dk_entries(ma_keys)
        #print "nentries:%s, dk_entries:%s" % (dk_nentries, dk_entries)
        self.dict = {}   # decoded underlying dictionary saved here.
        created[self.address] = self  # populate created dict so that circular reference can be handled when we construct the following dict.
        for i in range(dk_nentries):
            key = dk_entries[i]["me_key"]
            if self.splitted:
                val = ma_values[i]
            else:
                val = dk_entries[i]["me_value"]
            #print "key: %s, val: %s" % (key, val)
            if long(val) != 0:
                self.dict[PyObj(key, created, shallow)] = PyObj(val, created, shallow)
        assert len(self.dict) == ma_used, (len(self.dict), ma_used)

    def _dk_entries(self, ma_keys):
        # Assuming 64bit arch, do following:
        # define DK_ENTRIES(dk)  ((PyDictKeyEntry*)(&(dk)->dk_indices.as_1[DK_SIZE(dk) * DK_IXSIZE(dk)]))
        dk_size = long(ma_keys["dk_size"])
        if dk_size < 0xff:
            factor = 1
        elif dk_size < 0xffff:
            factor = 2
        elif dk_size < 0xffffffff:
            factor = 4
        else:
            factor = 8
        return ma_keys["dk_indices"]["as_1"][dk_size * factor].address.cast(PYDICTKEYENTRY_PTR)

    def str_dict(self):
        d = {}
        for k,v in self.dict.items():
            k = k.buf if type(k) is PyASCIIObject else k
            v = v.buf if type(v) is PyASCIIObject else v
            d[k] = v
        return d

    def __str__(self):
        return "dict(%s, %s)" % (len(self.dict), repr(self.dict))


class PyListObject(PyVarObject):
    def __init__(self, address, created={}, shallow=False):
        super(PyListObject, self).__init__(address)
        self.val = self.val.cast(PYLISTOBJECT_PTR)
        self.list = []
        created[self.address] = self  # populate created dict so that circular reference can be handled when we construct the following list.
        for i in range(self.ob_size):
            e = self.val["ob_item"][i]
            self.list.append(PyObj(e, created, shallow))

    def __str__(self):
        return "list(%d, %s)" % (len(self.list), repr(self.list))


class PyTupleObject(PyVarObject):
    def __init__(self, address, created={}, shallow=False):
        super(PyTupleObject, self).__init__(address)
        self.val = self.val.cast(PYTUPLEOBJECT_PTR)
        items = []
        created[self.address] = self  # populate created dict so that circular reference can be handled when we construct the following tuple.
        for i in range(self.ob_size):
            e = self.val["ob_item"][i]
            items.append(PyObj(e, created, shallow))
        self.tuple = tuple(items)

    def __str__(self):
        return "tuple(%d, %s)" % (len(self.tuple), repr(self.tuple))


class PyLongObject(PyVarObject):
    def __init__(self, address):
        super(PyLongObject, self).__init__(address)
        self.val = self.val.cast(PYLONGOBJECT_PTR)
        self.long = 0
        SHIFT = 30  # TODO: assert SHIFT is 30 in the system
        for i in range(abs(self.ob_size)):
            d = long(self.val["ob_digit"][i])
            self.long += d * (1L << (i*SHIFT))
        if self.ob_size < 0:
            self.long = -self.long

    def __str__(self):
        return str(self.long)

class PyBoolObject(PyLongObject):
    def __init__(self, address):
        super(PyBoolObject, self).__init__(address)
        self.bool = self.long != 0L

    def __str__(self):
        return str(self.bool)



class PyFrameObject(PyVarObject):
    '''
    Representing frame object.
    '''
    def __init__(self, address):
        super(PyFrameObject, self).__init__(address)
        self.val = self.val.cast(PYFRAMEOBJECT_PTR)
        self.globals = PyObj(self.val['f_globals'], shallow=True) # global symbol table
        self.locals = PyObj(self.val['f_locals'], shallow=True)   # local symbol table
        self.code = PyObj(self.val['f_code'], shallow=True)
        self.back_frame = long(self.val['f_back'])
        self.lineno = long(self.val['f_lineno'])
        self.localsplus = []  # locals+stack variables.

        i = 0
        valuestack =  self.val['f_valuestack'].dereference().address
        stacktop = self.val['f_stacktop'].dereference().address
        end = stacktop if stacktop else valuestack
        while self.val['f_localsplus'][i].address < end:
            self.localsplus.append(PyObj(self.val['f_localsplus'][i], shallow=True))
            i += 1

    def __str__(self):
        return "frame(0x%x, back=0x%x, code=%s, locals=%s, globals=%s, localsplus=%s)" % (
                    self.address, self.back_frame, self.code, self.locals, self.globals, self.localsplus)

    def _frame_chain(self):
        chain = [self]
        while chain[-1].back_frame:
            chain.append(PyFrameObject(chain[-1].back_frame))
        return chain

    def frame_chain(self):
        return ' <- '.join(hex(f.address) for f in self._frame_chain())

    def backtrace(self):
        ''' Get backtrace starting from this frame '''
        line = []
        for frame in self._frame_chain():
            code = PyCodeObject(frame.code.address)
            line.append('0x%-16x %-28s %s:%s' % (frame.address, code.name, code.filename, frame.lineno))
        return '\n'.join(line)


class PyCodeObject(PyObject):
    '''
    Representing code object
    '''
    def __init__(self, address):
        super(PyCodeObject, self).__init__(address)
        self.val = self.val.cast(PYCODEOBJECT_PTR)
        self.nlocals = long(self.val['co_nlocals'])       # number of local variables
        self.stacksize = long(self.val['co_stacksize'])   # number of entries needed for evaluation stack
        self.filename = PyASCIIObject(self.val['co_filename'])
        self.firstlineno = long(self.val['co_firstlineno'])
        self.name = PyASCIIObject(self.val['co_name'])
        self.code = PyObject(self.val['co_code'])

    def __str__(self):
        return 'code(%s:%s, %s, nlocals=%s, stacksize=%s, %s)' % (self.filename, self.firstlineno, self.name, self.nlocals, self.stacksize, self.code)


class PyModuleObject(PyObject):
    '''
    Representing module object
    '''
    def __init__(self, address, created={}):
        super(PyModuleObject, self).__init__(address)
        self.val = self.val.cast(PYMODULEOBJECT_PTR)
        self.name = PyASCIIObject(self.val['md_name'])
        created[self.address] = self  # populate created dict so that circular reference can be handled when we construct the following dict.
        self.dict = PyDictObject(self.val['md_dict'], created, shallow=True)

    def __str__(self):
        return 'module(%s, %s)' % (self.name, self.dict)  # use shallow_str to avoid recursion


# generator, async_generator, coroutine are very similar objects. (they all have detached frame chain)
class PyGenObject(PyObject):
    '''
    Representing generator object
    '''
    def __init__(self, address, PREFIX='gi', TYPE=PYGENOBJECT_PTR):
        super(PyGenObject, self).__init__(address)
        self.val = self.val.cast(TYPE)
        self.frame = PyFrameObject(self.val[PREFIX + '_frame'])
        self.name = PyObj(self.val[PREFIX + '_name'])
        self.qualname = PyObj(self.val[PREFIX + '_qualname'])
        self.code = PyObj(self.val[PREFIX + '_code'])
        self.running = long(self.val[PREFIX + '_running'])

    def backtrace(self):
        return self.frame.backtrace()

    def __str__(self):
        return 'generator(%s, %s, running=%s, %s, %s)' % (self.name, self.qualname, self.running, self.frame, self.code)


class PyAsyncGenObject(PyGenObject):
    '''
    Representing async_generator object
    '''
    def __init__(self, address):
        super(PyAsyncGenObject, self).__init__(address, PREFIX='ag', TYPE=PYASYNCGENOBJECT_PTR)
        self.closed = long(self.val['ag_closed'])

    def __str__(self):
        return 'async_generator(%s, %s, running=%s, closed=%s, %s, %s)' % (self.name, self.qualname, self.running, self.closed, self.frame, self.code)


class PyCoroObject(PyGenObject):
    '''
    Representing coroutine object
    '''
    def __init__(self, address):
        super(PyCoroObject, self).__init__(address, PREFIX='cr', TYPE=PYCOROOBJECT_PTR)

    def __str__(self):
        return 'coroutine(%s, %s, running=%s, %s, %s)' % (self.name, self.qualname, self.running, self.frame, self.code)


class PyFunctionObject(PyObject):
    '''
    Representing function object
    '''
    def __init__(self, address):
        super(PyFunctionObject, self).__init__(address)
        self.val = self.val.cast(PYFUNCTIONOBJECT_PTR)
        self.code = PyCodeObject(self.val['func_code'])
        self.name = PyASCIIObject(self.val['func_name'])
        self.qualname = PyASCIIObject(self.val['func_qualname'])
        self.module = PyObj(self.val['func_module'], shallow=True)
        self.globals = PyObj(self.val['func_globals'], shallow=True)
        self.dict = PyObj(self.val['func_dict'], shallow=True)
        self.defaults = PyObj(self.val['func_defaults'], shallow=True)  # default args
        self.kwdefaults = PyObj(self.val['func_kwdefaults'], shallow=True) # default kwargs
        self.closure = PyObj(self.val['func_closure'], shallow=True)   # closure cell objects

    def __str__(self):
        return 'function(%s, %s, module=%s, globals=%s, dict=%s, defaults=%s, kwdefaults=%s, closure=%s, %s)' % (
                self.name, self.qualname, self.module, self.globals, self.dict, self.defaults, self.kwdefaults, self.closure, self.code)


class PyMethodObject(PyObject):
    '''
    Representing method object
    '''
    def __init__(self, address):
        super(PyMethodObject, self).__init__(address)
        self.val = self.val.cast(PYMETHODOBJECT_PTR)
        self.self = PyObj(self.val['im_self'])
        self.func = PyObj(self.val['im_func'])

    def __str__(self):
        return 'method(self=%s, func=%s)' % (self.self, self.func)

class PyThreadState(object):
    '''
    Representing PyThreadState struct (not a PyObject)
    '''
    def __init__(self, address):
        if type(address) is gdb.Value:
            self.val = address
        else:
            self.val = gdb.Value(address)
        self.val = self.val.cast(PYTHREADSTATE_PTR)
        self.address = long(self.val)

        self.prev = long(self.val['prev'])
        self.next = long(self.val['next'])
        self.thread_id = long(self.val['thread_id'])
        self.interp = long(self.val['interp'])
        self.frame = PyFrameObject(self.val['frame'])
        self.dict = PyDictObject(self.val['dict'])

    def __str__(self):
        return 'thread(id=%s, interp=0x%x, %s, prev=0x%x, next=0x%x, dict=%s)' % (self.thread_id, self.interp, self.frame, self.prev, self.next, self.dict)


class PyInterpreterState(object):
    '''
    Rrepresenting PyInterpreterState struct (not a PyObject):
    '''
    def __init__(self, address):
        if type(address) is gdb.Value:
            self.val = address
        else:
            self.val = gdb.Value(address)
        self.val = self.val.cast(PYINTERPRETERSTATE_PTR)
        self.address = long(self.val)

        self.next = long(self.val['next'])
        self.modules = PyObject(self.val['modules'])
        self.builtins = PyObject(self.val['builtins'])
        self.sysdict = PyObject(self.val['sysdict'])
        self.importlib = PyObject(self.val['importlib'])

    def __str__(self):
        return 'interp(next=0x%x, modules=%s, builtins=%s, sysdict=%s, importlib=%s)' % (self.next, self.modules, self.builtins, self.sysdict, self.importlib)


def get_current_thread():
    ts = gdb.parse_and_eval("_PyThreadState_Current")  # global variable for current thread.
    return PyThreadState(ts["_value"])


def get_all_threads():
    cur_thread = get_current_thread()
    threads = [cur_thread]
    # traverse .next pointer
    cur = cur_thread.next
    while cur:
        thr = PyThreadState(cur)
        threads.append(thr)
        cur = thr.next
    # traverse .prev pointer
    cur = cur_thread.prev
    while cur:
        thr = PyThreadState(cur)
        threads.append(thr)
        cur = thr.prev
    return threads


def get_all_interpreters():
    cur_thread = get_current_thread()
    cur_interp = PyInterpreterState(cur_thread.interp)
    interps = [cur_interp]
    cur = cur_interp.next
    while cur:
        interp = PyInterpreterState(cur)
        interps.append(interp)
        cur = interp.next
    return interps

def thread_dump():
    for t in get_all_threads():
        print "---------------  Thread %s (0x%x): ------------------" % (t.thread_id, t.address)
        print t.frame.backtrace()

def module_dump():
    for interp in get_all_interpreters():
        print "--------------  Interpreter 0x%x -------------------" % (interp.address)
        for k, v in PyDictObject(interp.modules.address, {}, shallow=True).dict.items():
            print "module  0x%-16x  %s" % (v.address, k)

def PyObj(address, created={}, shallow=False):
    '''
    :param address:  gdb.Value or integer representing memory address
    :param created:  dict of already created obj (address -> obj). Used to create objects that can references each other.
    :param shallow:  shallowly inspect the object; do not dig into it. (Could be expensive in some cases)
    Inspect its type info, and create appropriate object
    '''
    if long(address) == 0:
        # NULL ptr
        return 0
    if long(address) in created:
        # The object pointed by the address has already been created
        return created[long(address)]
    tp = PyObject.typename(address)

    # Atom object (thoses that could not form circular references)
    if tp == 'str':
        strobj = PyASCIIObject(address)
        if strobj.ascii and strobj.compact:
            return strobj
        # TODO: support other type of strings
        return PyObject(address)
    elif tp == 'bool':
        return PyBoolObject(address)
    elif tp == 'long' or tp == 'int':
        return PyLongObject(address)
    elif tp == 'NoneType':
        return None

    # Complex object that could form circular references
    if shallow:
        return PyObject(address)
    elif tp == 'dict':
        return PyDictObject(address, created)
    elif tp == 'list':
        return PyListObject(address, created)
    elif tp == 'tuple':
        return PyTupleObject(address, created)
    elif tp == 'type':
        return PyTypeObject(address)
    elif tp == 'frame':
        return PyFrameObject(address)
    elif tp == 'code':
        return PyCodeObject(address)
    elif tp == 'module':
        return PyModuleObject(address, created)
    elif tp == 'generator':
        return PyGenObject(address)
    elif tp == 'async_generator':
        return PyAsyncGenObject(address)
    elif tp == 'coroutine':
        return PyCoroObject(address)
    elif tp == 'function':
        return PyFunctionObject(address)
    elif tp == 'method':
        return PyMethodObject(address)
    else:
        # not recognized type
        return PyObject(address)
