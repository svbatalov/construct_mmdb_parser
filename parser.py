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
def pointer(data_offset):
    return c.Struct(
        "ctrl" / Ctrl, # * check_type(1),
        c.Check(c.this.ctrl.type == 1),
        "value" / c.Pointer(c.this.ctrl.len + data_offset, c.LazyBound(lambda: DataEntry)),
    )

Str = c.Struct(
    "ctrl" / Ctrl, # * check_type(2),
    c.Check(c.this.ctrl.type == 2),
    "value" / c.PaddedString(c.this.ctrl.len, "utf8"),
)

Int = (c.Struct(
    "ctrl" / Ctrl, # * check_type([5, 6, 8, 9, 10]),
    c.Check(lambda this: this.ctrl.type in [5, 6, 8, 9, 10]),
    "value" / c.BytesInteger(c.this.ctrl.len),
))

Arr = c.Struct(
    "ctrl" / Ctrl, # * check_type(11),
    c.Check(c.this.ctrl.type == 11),
    "value" / c.LazyBound(lambda: DataEntry),
    # c.Probe(lookahead=10)
)

Map = c.Struct(
    "ctrl" / Ctrl, # * check_type([7]),
    c.Check(c.this.ctrl.type == 7),
    "map_key" / Str,
    "map_value" / c.LazyBound(lambda: DataEntry),
)

DataEntry = c.Select(
    Str,
    Int,
    Arr,
    Map,
)

class MMDB:
    def __init__(self, record_size=32, file=None):
        self.rs = record_size
        self.dss = b"\x00"*16
        self.mss = b"\xab\xcd\xefMaxMind.com"

        self.DataSectionSeparator = c.Const(self.dss)
        self.MetadataSectionSeparator = c.Const(self.mss)
        self.file = file

        self.find_section_offsets()
        print(f"Data section offset {self.ds_offset}\nMetadata section offset: {self.ms_offset}")
        data_size = self.ms_offset - self.ds_offset - len(self.dss)
        print(f"Data section size {data_size} bytes ({data_size / 1e6} MB)")

    def metadata(self):
        # print(self.DataEntry.parse(b"\x43abc"))
        # print(self.DataEntry.build(u"abc"))

        # print(self.DataEntry.parse(b"\xa1\x02"))
        # print(self.DataEntry.build(2))

        # print(self.DataEntry.parse(b""))

        return c.Sequence(
            c.Seek(self.ms_offset + len(self.mss)),
            c.GreedyRange(
                DataEntry #* self.printobj()
            ),
        )

    def read_metadata(self):
        self.meta = self.metadata().parse_file(self.file)
        return self.meta

    def printobj(self, limit=None, show=True):
        def func(obj, ctx):
            if show:
                print(obj, ctx)

            # if obj.left > 11889298:
            #     raise c.CancelParsing

            if limit and ctx and ctx._index and ctx._index > limit:
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
        return c.Sequence(
            c.Seek(self.ds_offset + len(self.dss)),
            DataEntry,
            c.Probe(lookahead=10),
            c.HexDump(c.GreedyBytes),
            # c.GreedyRange(
            #     DataEntry * self.printobj(limit=limit, show=show),
            #     discard=discard
            # ),
            c.Probe(lookahead=10, into=c.this)
        )
    
    def read_data(self, limit=None, show=False):
        return self.data(limit=limit, show=show).parse_file(m.file)

# MMDB(file="/tmp/anycast_ranges_only.mmdb").tree()

# r = c.Struct(
#     "tree" / MMDB().tree(discard=True),
#     "dss" / c.Const(b"DSS"),
#     "data" / c.GreedyBytes
# ).parse(b"\x00\x00\x00\x01\x00\xb5\x6a\x92\x00\x00\x00\x01\x00\xb5\x6a\x92\x00\x00\x00\x01\x00\xb5\x6a\x92DSSsome data")
# # ).parse_file("/tmp/anycast_ranges_only.mmdb")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('file', nargs='?')
    args = parser.parse_args()
    print(args)

    m = MMDB(file=args.file)
    meta = m.read_metadata()
    print(meta)

    # print("node_count", meta.search("node_count"))

    d = m.read_data(limit=10)
    print(d)
