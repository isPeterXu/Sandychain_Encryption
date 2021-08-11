import json
from charm.toolbox.pairinggroup import PairingGroup
group = PairingGroup('MNT224')


class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, str):
            return obj
        else:
            return str(group.serialize(obj), encoding='utf-8')
        # if isinstance(obj, bytes):
        #     return str(obj, encoding='utf-8')
        # return json.JSONEncoder.default(self, obj)


