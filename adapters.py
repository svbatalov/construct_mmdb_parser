import construct as c

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

