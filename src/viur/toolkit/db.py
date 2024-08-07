import logging
import time
import typing as t

from viur.core import bones, db, skeleton

__all__ = [
    "normalize_key",
    "write_in_transaction",
    "increase_counter",
    "set_status",
]

logger = logging.getLogger(__name__)

_KeyType: t.TypeAlias = str | db.Key


def normalize_key(key: _KeyType) -> db.Key:
    if isinstance(key, str):
        return db.Key.from_legacy_urlsafe(key)
    elif isinstance(key, db.Key):
        return key
    raise TypeError(f"Expected key of type str or db.Key, got: {type(key)}")


def write_in_transaction(key: _KeyType, create_missing_entity: bool = True, **values: t.Any) -> db.Entity:
    def txn(_key: db.Key, _values: dict[str, t.Any]) -> db.Entity:
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
    def txn(_key: db.Key, _name: str, _value: float | int, _start: float | int) -> float | int:
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
    values: dict | t.Callable[[skeleton.SkeletonInstance | db.Entity], None],
    precondition: t.Optional[dict | t.Callable[[skeleton.SkeletonInstance | db.Entity], None]] = None,
    create: dict[str, t.Any] | t.Callable[[skeleton.SkeletonInstance | db.Entity], None] | bool = False,
    skel: t.Optional[skeleton.SkeletonInstance] = None,
    update_relations: bool = False,
    retry: int = 1,
) -> skeleton.SkeletonInstance | db.Entity:
    """
    Universal function to set values of an entity within a transaction.
    It is mostly used for status changes, but can also change any value.

    :param key: Entity key to change
    :param values: A dict of key-values to update on the entry, or a callable that is executed within the transaction
    :param precondition: An optional dict of key-values to check on the entry before; can also be a callable.
    :param create: When key does not exist, create it, optionally with values from provided dict, or in a callable.
    :param skel: Use assigned skeleton instead of low-level DB-API
    :param update_relations: Trigger update relations task on success (only in skel-mode, defaults to False)
    :param retry: On ViurDatastoreError, retry for this amount of times.

    If the function does not raise an Exception, all went well.
    It returns either the assigned skel, or the db.Entity on success.
    """

    # Transactional function
    def transaction() -> skeleton.SkeletonInstance | db.Entity:
        exists = True

        # Use skel or db.Entity
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

        # Handle create
        if not exists and create:
            if isinstance(create, dict):
                for bone, value in create.items():
                    obj[bone] = value
            elif callable(create):
                create(obj)

        # Handle precondition
        if isinstance(precondition, dict):
            for bone, value in precondition.items():
                if obj[bone] != value:
                    raise ValueError(f"{bone} contains {obj[bone]!r}, expecting {value!r}")

        elif callable(precondition):
            precondition(obj)

        # Set values
        if isinstance(values, dict):
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

        elif callable(values):
            values(obj)

        else:
            raise ValueError("'values' must either be dict or callable.")

        if skel:
            assert skel.toDB(update_relations=update_relations)
        else:
            db.Put(obj)

        return obj

    # Retry loop
    while True:
        try:
            return db.RunInTransaction(transaction)

        except db.ViurDatastoreError as e:
            retry -= 1
            if retry <= 0:
                raise

            logging.debug(f"{e}, retrying {retry} more times")

        time.sleep(1)
