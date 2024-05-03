import logging
import typing as t

from viur.core import db

__all__ = [
    "normalize_key",
    "write_in_transaction",
    "increase_counter",
]

logger = logging.getLogger(__name__)

_KeyType: t.TypeAlias = str | db.Key


def normalize_key(key: _KeyType) -> db.Key:
    if isinstance(key, str):
        return db.Key.from_legacy_urlsafe(key)
    elif isinstance(key, db.Key):
        return key
    raise TypeError(f"Expected key of type str or db.Key, got: {type(key)}")


def write_in_transaction(key: _KeyType, create_missing_entity: bool = True, **values):
    def txn(_key, _values):
        try:
            entity = db.Get(_key)
        except db.NotFoundError:
            if create_missing_entity:
                entity = db.Entity(_key)
            else:
                raise
        for k, v in _values.items():
            entity[k] = v
        db.Put(entity)
        return entity

    return db.RunInTransaction(txn, normalize_key(key), values)


def increase_counter(key: _KeyType, name: str, value: float | int = 1, start: float | int = 0) -> int | float:
    def txn(_key, _name, _value, _start):
        try:
            entity = db.Get(_key)
        except db.NotFoundError:
            # Use not db.GetOrInsert here, we write the entity later anyway
            # and can therefore save the db.Put in db.GetOrInsert
            entity = db.Entity(_key)

        if _name not in entity:
            entity[_name] = _start
        old_value = entity[_name]
        entity[_name] += _value
        db.Put(entity)
        return old_value

    return db.RunInTransaction(txn, normalize_key(key), name, value, start)
