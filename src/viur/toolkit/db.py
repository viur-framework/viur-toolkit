from viur.core import db

__all__ = [
    "getNewEntityForKey",
    "normalizeKey",
    "writeInTransaction",
    "increaseCounter",
]


def getNewEntityForKey(key):
    return db.Entity(key)


def normalizeKey(key):
    if isinstance(key, str):
        return db.Key(encoded=key)
    elif isinstance(key, db.Key):
        return key
    raise TypeError("Expected key of type str or db.Key, got: %r" % type(key))


def writeInTransaction(key, createMissingEntity=True, **values):
    def txn(_key, _values):
        try:
            entity = db.Get(_key)
        except db.NotFoundError:
            if createMissingEntity:
                entity = getNewEntityForKey(_key)
            else:
                raise

        for k, v in list(_values.items()):
            entity[k] = v
        db.Put(entity)
        return entity

    return db.RunInTransaction(txn, normalizeKey(key), values)


def increaseCounter(key, name, value=1, start=0):
    def txn(_key, _name, _value, _start):
        try:
            entity = db.Get(_key)
        except db.NotFoundError:
            # Use not db.GetOrInsert here, we write the entity later anyway
            # and can therefore save the db.Put in db.GetOrInsert
            entity = getNewEntityForKey(_key)

        if _name not in entity:
            entity[_name] = _start
        assignedValue = entity[_name]
        entity[_name] += _value
        db.Put(entity)
        return assignedValue

    return db.RunInTransaction(txn, normalizeKey(key), name, value, start)
