import construct as c
import mmap
import argparse

"""
https://maxmind.github.io/MaxMind-DB/
"""

# https://docs.python.org/3/library/mmap.html
def search_string_offset_in_file(file, strings):
    with open(file, "rb") as f:
        # 0 -- whole file
        mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
        offsets = []
        for s in strings:
            offsets.append(mm.find(s))

    return offsets

class MMDB:
    def __init__(self, record_size=32, file=None):
        self.rs = record_size
        self.dss = b"\x00"*16
        self.mss = b"\xab\xcd\xefMaxMind.com"

        self.DataSectionSeparator = c.Const(self.dss)
        self.MetadataSectionSeparator = c.Const(self.mss)
        self.file = file

        if file:
            self.ds_offset, self.ms_offset = search_string_offset_in_file(file, [
                b"\x00"*16,
                b"\xab\xcd\xefMaxMind.com"
            ])
            print(f"Data section offset {self.ds_offset}\nMetadata section offset: {self.ms_offset}")
            print(f"Data section size {self.ms_offset - self.ds_offset - len(self.dss)} bytes")

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

        self.Ctrl = c.BitStruct(
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

        self.Pointer = c.Struct(
            "ctrl" / self.Ctrl * self.check_type(1),
            "value" / c.Pointer(c.this.ctrl.len + self.ds_offset + len(self.dss), c.LazyBound(lambda: self.DataEntry)),
        )

        self.Str = c.Struct(
            "ctrl" / self.Ctrl * self.check_type(2),
            "value" / c.PaddedString(c.this.ctrl.len, "utf8"),
        )

        self.Int = (c.Struct(
            "ctrl" / self.Ctrl * self.check_type([5, 6, 8, 9, 10]),
            "value" / c.BytesInteger(c.this.ctrl.len),
        ))

        self.Arr = c.Struct(
            "ctrl" / self.Ctrl * self.check_type(11),
            "value" / c.LazyBound(lambda: self.DataEntry),
            # c.Probe(lookahead=10)
        )

        self.Map = c.Struct(
            "ctrl" / self.Ctrl * self.check_type([7]),
            "map_key" / self.Str,
            "map_value" / c.LazyBound(lambda: self.DataEntry),
        )

        self.DataEntry = c.Select(
            self.Str,
            self.Int,
            self.Arr,
            self.Map,
        )

    def check_type(self, vals):
        if type(vals) == list:
            def f(obj, _):
                if obj.type not in vals:
                    raise c.ConstructError()
        else:
            def f(obj, _):
                if obj.type != vals:
                    raise c.ConstructError()
        return f
        
    def metadata(self):
        # print(self.DataEntry.parse(b"\x43abc"))
        # print(self.DataEntry.build(u"abc"))

        # print(self.DataEntry.parse(b"\xa1\x02"))
        # print(self.DataEntry.build(2))

        # print(self.DataEntry.parse(b""))

        return c.Sequence(
            c.Seek(self.ms_offset + len(self.mss)),
            c.GreedyRange(
                self.DataEntry #* self.printobj
            ),
            # c.Probe(lookahead=10)
        ).parse_file(self.file)

    def printobj(self, obj, ctx):
        print(obj, ctx)
        # if obj.left > 11889298:
        #     raise c.CancelParsing
        # if ctx._index+1 >= 10:
        #     raise c.CancelParsing

    def record(self):
        return c.Bitwise(c.BitsInteger(self.rs))

    def tree(self, discard=True):
        Record = self.record()
        Node = c.Struct(
            "left" / Record,
            "right" / Record,
            "offset" / c.Tell
        )

        return c.GreedyRange(Node * self.printobj, discard=discard).parse_file(self.file)

    def find_section_offsets(self, file):
        pass
    def data(self):
        return c.Struct(
            c.GreedyBytes,
            self.DataSectionSeparator,

        )

# MMDB(file="/tmp/anycast_ranges_only.mmdb").tree()

# r = c.Struct(
#     "tree" / MMDB().tree(discard=True),
#     "dss" / c.Const(b"DSS"),
#     "data" / c.GreedyBytes
# ).parse(b"\x00\x00\x00\x01\x00\xb5\x6a\x92\x00\x00\x00\x01\x00\xb5\x6a\x92\x00\x00\x00\x01\x00\xb5\x6a\x92DSSsome data")
# # ).parse_file("/tmp/anycast_ranges_only.mmdb")

# print("RESULT:", r)

# print(search_string_offset_in_file("/tmp/anycast_ranges_only.mmdb", [b"\x00"*16, b"\xab\xcd\xefMaxMind.com"]))


# m = MMDB(file="/tmp/anycast_ranges_only.mmdb")
# t = m.tree().parse_file("/tmp/anycast_ranges_only.mmdb")

parser = argparse.ArgumentParser()
parser.add_argument('file', nargs='?')
args = parser.parse_args()
print(args)

m = MMDB(file=args.file)
meta = m.metadata()
print(meta)

# print("node_count", meta.search("node_count"))

d = c.Sequence(
    c.Seek(m.ds_offset + len(m.dss)),
    m.DataEntry
).parse_file(m.file)
print(d)
