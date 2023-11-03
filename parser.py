import construct as c
import mmap

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

        self.Type = c.BitStruct(
            "type" / c.BitsInteger(3),
            "len" / c.BitsInteger(5),
            # c.Probe(lookahead=32),
        )

        self.Pointer = c.Struct(
            "type" / self.Type * self.check_type(1),
            "value" / c.Pointer(c.this.type.len + self.ds_offset + len(self.dss), c.LazyBound(lambda: self.DataEntry)),
        )

        class StrAdapter(c.Adapter):
            def _decode(self, obj, context, path):
                return obj.value

            def _encode(self, obj, context, path):
                return dict(type=dict(type=2, len=len(obj)), value=obj)

        class IntAdapter(c.Adapter):
            def _decode(self, obj, context, path):
                return obj.value

            def _encode(self, obj, context, path):
                if type(obj) != int:
                    raise c.ConstructError()
                if obj < 256:
                    len = 1
                elif obj < 65536:
                    len = 2
                else:
                    len = 4
                return dict(type=dict(type=5, len=len), value=obj)

        class MapAdapter(c.Adapter):
            def _decode(self, obj, context, path):
                return obj.value

            def _encode(self, obj, context, path):
                if type(obj) != dict:
                    raise c.ConstructError()
                len = len(obj)
                return dict(type=dict(type=7, len=len), value=obj)

        # self.Str = (c.Struct(
        #     "type" / self.Type * self.check_type(2),
        #     "value" / c.PaddedString(c.this.type.len, "utf8"),
        # ))

        self.Str = (c.Struct(
            "type" / self.Type * self.check_type(2),
            "value" / c.Switch(c.this.type.len, {
                29: c.Struct(
                    "size1" / c.BytesInteger(1),

                )
            }, default=c.PaddedString(c.this.type.len, "utf8")),
            
        ))

        self.Int = (c.Struct(
            "type" / self.Type * self.check_type([5, 6]),
            "value" / c.BytesInteger(c.this.type.len),
        ))

        self.IntExt = c.Struct(
            "type" / self.Type * self.check_type(0),
            "subtype" / c.BytesInteger(1),
            "full_type" / c.Computed(c.this.subtype + 7) * self.check_full_type([8, 9, 10]),
            "value" / c.BytesInteger(c.this.type.len),
        )

        self.Arr = c.Struct(
            "type" / self.Type * self.check_type(0),
            "subtype" / c.BytesInteger(1),
            "full_type" / c.Computed(c.this.subtype + 7) * self.check_full_type([11]),
            # "value" / c.Array(c.this.type.len, c.LazyBound(lambda: self.DataEntry)),
            "value" / self.Str,
            # c.Probe(lookahead=10)
        )

        self.Map = c.Struct(
            "type" / self.Type * self.check_type([7]),
            "map_key" / self.Str,
            "map_value" / c.LazyBound(lambda: self.DataEntry),
        )

        self.DataEntry = c.Select(
            self.Str,
            self.Int,
            self.IntExt,
            self.Arr,
            self.Map,
            # c.Probe(),
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
        
    def check_full_type(self, vals):
        def f(obj, _):
            if obj not in vals:
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
            c.Probe(lookahead=10)
        ).parse_file(self.file)

    def printobj(self, obj, ctx):
        print(obj)
        if obj.left > 11889298:
            raise c.CancelParsing
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

MMDB(file="/tmp/anycast_ranges_only.mmdb").tree()

# r = c.Struct(
#     "tree" / MMDB().tree(discard=True),
#     "dss" / c.Const(b"DSS"),
#     "data" / c.GreedyBytes
# ).parse(b"\x00\x00\x00\x01\x00\xb5\x6a\x92\x00\x00\x00\x01\x00\xb5\x6a\x92\x00\x00\x00\x01\x00\xb5\x6a\x92DSSsome data")
# # ).parse_file("/tmp/anycast_ranges_only.mmdb")

# print("RESULT:", r)

# print(search_string_offset_in_file("/tmp/anycast_ranges_only.mmdb", [b"\x00"*16, b"\xab\xcd\xefMaxMind.com"]))


m = MMDB(file="/tmp/anycast_ranges_only.mmdb")
# m = MMDB(file="/tmp/anycast_v4.mmdb")
meta = m.metadata()
print(meta)
# print(meta.search("node_count"))

# t = m.tree().parse_file("/tmp/anycast_ranges_only.mmdb")
