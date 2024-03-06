from viur.core import conf, current, db

__all__ = ["contains_substring", "user_has_access"]


def contains_substring(haystack: str, *needles: str) -> bool:
    """Check if *haystack* contains one of the *needles* as substring."""
    return any(needle in haystack for needle in needles)


def user_has_access(*roles: str, user: db.Key | None = None) -> bool:
    """Check if the user has one of the given roles."""
    if user is None:  # this None acts as sentinel
        user = current.user.get()
        if user is None:
            return False  # guests have no access
    elif isinstance(user, db.Key):
        _key = user
        user = conf.main_app.vi.user.viewSkel()
        user.fromDB(_key)
    else:
        raise ValueError(f"Invalid value for user: {user!r}")

    return any(role in user["access"] for role in roles)
