
import dataclasses
from enum import Enum

def serialize_enum(value):
    if isinstance(value, Enum):
        return value.value
    return value

def enum_from_value(enum_cls, val):
    return enum_cls(val)

def dataclass_to_dict(obj):
    return {k: serialize_enum(v) for k, v in dataclasses.asdict(obj).items()}

def dataclass_from_dict(cls, data):
    field_types = {f.name: f.type for f in dataclasses.fields(cls)}
    return cls(**{
        k: (enum_from_value(field_types[k], v) if issubclass(field_types[k], Enum) else v)
        for k, v in data.items()
    })
