from os import walk
import construct as c
import mmap
import argparse

"""
https://maxmind.github.io/MaxMind-DB/
"""

## Finds offsets in bytes of the given strings in the file.
## https://docs.python.org/3/library/mmap.html
def search_string_offset_in_file(file, strings):
    with open(file, "rb") as f:
        # 0 -- whole file
        mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
        offsets = []
        for s in strings:
            offsets.append(mm.find(s))

    return offsets

## Auxiliary helpers
def check_type(vals):
    if type(vals) == list:
        def f(obj, _):
            if obj.type not in vals:
                raise c.ConstructError()
    else:
        def f(obj, _):
            if obj.type != vals:
                raise c.ConstructError()
    return f

def ext_type(this):
    if this.type1 == 0 and this.ext_type:
        return 7 + this.ext_type
    return this.type1

def ext_len(this):
    if this.len1 == 29:
        return 29 + this.ext_len
    if this.len1 == 30:
        return 285 + this.ext_len
    if this.len1 == 31:
        return 65821 + this.ext_len
    return this.len1

## Parsers
Ctrl = c.BitStruct(
    "type1" / c.BitsInteger(3),
    "len1" / c.BitsInteger(5),
    "ext_type" / c.If(c.this.type1 == 0, c.BitsInteger(8)),  # Additional control byte
    "ext_len" / c.Switch(c.this.len1, {
        29: c.BitsInteger(8),
        30: c.BitsInteger(16),
        31: c.BitsInteger(24),
    }),
    "type" / c.Computed(ext_type),
    "len" / c.Computed(ext_len),
)

## Returns a pointer parser with respect to a given data/metadata section offset
def Pointer(data_offset):
    return c.Struct(
        "pointer" / c.BitStruct(
            "type" / c.BitsInteger(3),
            c.Check(c.this.type == 1),
            "size" / c.BitsInteger(2),
            "value1" / c.BitsInteger(3),
            "value2" / c.BitsInteger((c.this.size+1) * 8),
            "offset" / c.Computed(c.this.value2 + (c.this.value1 << (c.this.size+1)*8)),
        ),
        # Seeking inside of BitStruct is not supported
        "value" / c.Pointer(c.this.pointer.offset + data_offset, c.LazyBound(lambda: DataEntry(data_offset))),
    )


Str = c.Struct(
    "ctrl" / Ctrl, # * check_type(2),
    c.Check(c.this.ctrl.type == 2),
    "value" / c.PaddedString(c.this.ctrl.len, "utf8"),
)

Double = c.Struct(
    "ctrl" / Ctrl,
    c.Check(c.this.ctrl.type == 3),
    "value" / c.Double,
)

Bytes = c.Struct(
    "ctrl" / Ctrl,
    c.Check(c.this.ctrl.type == 4),
    "value" / c.Bytes(c.this.ctrl.len),
)

Int = (c.Struct(
    "ctrl" / Ctrl, # * check_type([5, 6, 8, 9, 10]),
    c.Check(lambda this: this.ctrl.type in [5, 6, 8, 9, 10]),
    "value" / c.BytesInteger(c.this.ctrl.len),
))

def Arr(offset):
    return c.Struct(
        "ctrl" / Ctrl, # * check_type(11),
        c.Check(c.this.ctrl.type == 11),
        "value" / c.Array(
            c.this.ctrl.len,
            c.LazyBound(lambda: DataEntry(offset)),
        )
        # c.Probe(lookahead=10)
    )

Cache = c.Struct(
    "ctrl" / Ctrl,
    c.Check(c.this.ctrl.type == 12),
)

End = c.Struct(
    "ctrl" / Ctrl,
    c.Check(c.this.ctrl.type == 13),
)

Bool = c.Struct(
    "ctrl" / Ctrl,
    c.Check(c.this.ctrl.type == 14),
    "value" / c.Computed(c.this.ctrl.len)
)

def Map(offset):
    return c.Struct(
        "ctrl" / Ctrl,
        c.Check(c.this.ctrl.type == 7),
        "value" / c.Array(
            c.this.ctrl.len,
            c.Struct(
                # The spec says that keys are always UTF8 strings,
                # but in practice they can be pointers
                "map_key" / c.LazyBound(lambda: DataEntry(offset)),
                "map_value" / c.LazyBound(lambda: DataEntry(offset)),
            )
        )
    )

def DataEntry(offset):
    return c.Select(
        Str,
        Double,
        Bytes,
        Int,
        Arr(offset),
        Map(offset),
        Cache,
        End,
        Bool,
        Pointer(offset),
    )

class MMDB:
    def __init__(self, file=None):
        self.dss = b"\x00"*16
        self.mss = b"\xab\xcd\xefMaxMind.com"

        self.DataSectionSeparator = c.Const(self.dss)
        self.MetadataSectionSeparator = c.Const(self.mss)
        self.file = file

        self.find_section_offsets()
        self.data_start = self.ds_offset + len(self.dss)
        self.metadata_start = self.ms_offset + len(self.mss)
        data_size = self.ms_offset - self.ds_offset - len(self.dss)

        print(f"Data section offset {self.ds_offset} (data starts at {self.data_start})")
        print(f"Metadata section offset: {self.ms_offset} (metadata starts at {self.metadata_start})")
        print(f"Data section size {data_size} bytes ({data_size / 1e6} MB)")
        self.read_metadata()

    def metadata(self):
        Entry = DataEntry(self.metadata_start)
        return c.Sequence(
            c.Seek(self.metadata_start),
            c.GreedyRange(
                Entry #* self.printobj()
            ),
        )

    def read_metadata(self):
        self.meta = self.metadata().parse_file(self.file)
        values = self.meta.search_all("value")
        self.rs = values[values.index("record_size")+1]
        print(f"Record size: {self.rs}")
        return self.meta

    def printobj(self, limit=None, show=True):
        def func(obj, ctx):
            if show:
                print(obj, ctx)

            # if obj.left > 11889298:
            #     raise c.CancelParsing

            if limit and ctx and ctx._index and ctx._index >= limit:
                raise c.CancelParsing
        return func

    def tree(self, discard=True):
        ## TODO: Implement node layout for 28 bit DB
        ## TODO: Get record size (rs) from metadata
        Record = c.Bitwise(c.BitsInteger(self.rs))

        Node = c.Struct(
            "left" / Record,
            "right" / Record,
            "offset" / c.Tell
        )

        return c.GreedyRange(Node * self.printobj(), discard=discard).parse_file(self.file)

    def find_section_offsets(self):
        if not self.file:
            raise FileNotFoundError

        self.ds_offset, self.ms_offset = search_string_offset_in_file(self.file, [
            b"\x00"*16,
            b"\xab\xcd\xefMaxMind.com"
        ])

    def data(self, limit=None, show=False, discard=False):
        Entry = DataEntry(self.data_start)
        return c.Sequence(
            c.Seek(self.data_start),
            c.GreedyRange(
                Entry * self.printobj(limit=limit, show=show),
                discard=discard
            ),
        )
    
    def read_data(self, limit=None, show=False):
        return self.data(limit=limit, show=show).parse_file(m.file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('file', nargs='?')
    args = parser.parse_args()
    print(args)

    m = MMDB(file=args.file)

    print("Metadata:\n", m.meta)

    d = m.read_data(limit=3)
    print(d)
