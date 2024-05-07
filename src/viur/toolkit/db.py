import logging
import typing as t

from viur.core import db, skeleton, bones

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


def set_status(
    key: _KeyType,
    values: t.Dict = None,
    check: t.Dict = None,
    create: [t.Dict, bool] = None,
    func: callable = None,
    skel: skeleton.SkeletonInstance = None,
    update_relations: bool = False
):
    """
    Universal function to set a status of an entity within a transaction.

    :param key: Entity key to change
    :param values: A dict of key-values to update on the entry
    :param check: An optional dict of key-values to check on the entry before
    :param create: When key does not exist, create it, optionally with values from provided dict.
    :param func: A function that is called inside the transaction
    :param skel: Use assigned skeleton instead of low-level DB-API
    :param update_relations: Trigger update relations task on success (only in skel-mode, defaults to False)

    If the function does not raise an Exception, all went well.
    It returns either the assigned skel, or the db.Entity on success.
    """
    if callable(values):
        assert not func, "'values' is a callable, but func is also set. Either set values or func in this case."
        func = values
        values = None

    assert isinstance(values, dict) or values is None, "'values' has to be a dict when set"

    def transaction():
        exists = True

        if skel:
            if not skel.fromDB(key):
                if not create:
                    raise ValueError(f"Entity {key=} not found")

                skel["key"] = key
                exists = False

            obj = skel
        else:
            obj = db.Get(key)

            if obj is None:
                if not create:
                    raise ValueError(f"Entity {key=} not found")

                obj = db.Entity(key)
                exists = False

        if not exists and isinstance(create, dict):
            for bone, value in create.items():
                obj[bone] = value

        if check:
            assert isinstance(check, dict), "'check' has to be a dict, you diggi!"

            for bone, value in check.items():
                assert obj[bone] == value, "%r contains %r, expecting %r" % (bone, obj[bone], value)

        if values:
            for bone, value in values.items():
                # Increment by value?
                if bone[0] == "+":
                    obj[bone[1:]] += value
                # Decrement by value?
                elif bone[0] == "-":
                    obj[bone[1:]] -= value
                else:
                    if skel and (
                        (boneinst := getattr(skel, bone, None))
                        and isinstance(boneinst, bones.RelationalBone)
                    ):
                        assert skel.setBoneValue(bone, value)
                        continue

                    obj[bone] = value

        if func and callable(func):
            func(obj)

        if skel:
            assert skel.toDB(update_relations=update_relations)
        else:
            db.Put(obj)

        return obj

    return db.RunInTransaction(transaction)
