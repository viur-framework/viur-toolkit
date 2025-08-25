"""
Helper for ViUR-core types and behavior
"""

import logging
import typing as t

from viur.core import current, db, i18n
from viur.core.skeleton import SkeletonInstance, skeletonByKind

__all__ = [
    "change_language",
    "get_task_retry_count",
    "without_render_preparation",
    "get_full_skel_from_ref_skel",
    "iter_skel",
    "ensure_translation",
]

logger = logging.getLogger(__name__)


def change_language(lang: str) -> None:
    """Change the current language"""
    current.session.get()["lang"] = lang
    current.language.set(lang)


def get_task_retry_count() -> int:
    """Return the number of times the current task is retried as int"""
    try:
        return int(current.request.get().request.headers.get("X-Appengine-Taskretrycount", -1))
    except AttributeError:
        # During warmup current.request is None (at least on local devserver)
        return -1


def without_render_preparation(skel: SkeletonInstance, full_clone: bool = False) -> SkeletonInstance:
    """Return the SkeletonInstance without renderPreparation.

    This method is useful (and unfortunately necessary due to the ViUR design)
    if you call python methods from the jinja template that should work on the
    `SkeletonInstance.accessedValues` and not on the `SkeletonInstance.renderAccessedValues`.

    If the SkeletonInstance does not have renderPreparation, it will be returned as is.
    If renderPreparation is enabled, a new SkeletonInstance is created.
    However, unless `full_clone` is True, the SkeletonInstance will use the
    identical objects as the source skeleton. It just "removes" the
    "renderPreparation mode" and keep it for the source skel enabled.
    """
    if skel.renderPreparation is not None:
        # TODO: ViUR, I DONT WANT TO HAVE RENDERPREPARATION ON MODULE LAYER!!!
        if full_clone:
            skel = skel.clone()
        else:
            src_skel = skel
            # Create a new SkeletonInstance with the same object,
            # but without enabled renderPreparation
            skel = SkeletonInstance(src_skel.skeletonCls, bone_map=src_skel.boneMap)
            skel.accessedValues = src_skel.accessedValues
            skel.dbEntity = src_skel.dbEntity
            skel.errors = src_skel.errors
            skel.is_cloned = src_skel.is_cloned
        assert skel.renderPreparation is None
    return skel


def get_full_skel_from_ref_skel(ref_skel: SkeletonInstance) -> SkeletonInstance:
    kind_name = ref_skel.skeletonCls.__name__.removeprefix("RefSkelFor")
    skel: SkeletonInstance = skeletonByKind(kind_name)()  # noqa
    skel.fromDB(ref_skel["key"])
    return skel


def iter_skel(query: db.Query) -> t.Iterator[SkeletonInstance]:
    """Fetch all entries for this query and yield the skel

    Doesn't use fetch() due to the strange ViUR fetch limit (100).
    Acts as generator to be not memory hungry...
    """
    skel: SkeletonInstance = query.srcSkel
    for entry in query.iter():
        skel = SkeletonInstance(skel.skeletonCls, clonedBoneMap=skel.boneMap)
        skel.setEntity(entry)
        db.currentDbAccessLog.get(set()).add(skel["key"])
        try:
            yield skel
        except GeneratorExit:
            logger.warning("GeneratorExit. Stop iteration.")
            break


def ensure_translation(value: str | i18n.translate, *args: t.Any, **kwargs: t.Any) -> i18n.translate | None:
    """
    Ensure that the given value is an ``i18n.translate`` object.

    If the input value is already an instance of ``i18n.translate``, it is returned unchanged.
    If the value is a string, it will be converted to an ``i18n.translate`` object using the
    provided arguments.
    If the value is ``None``, the function returns ``None``.

    :param value: The value to ensure as a translation object.
    :param args: Additional positional arguments passed to the ``i18n.translate`` constructor if ``value`` is a string.
    :param kwargs: Additional keyword arguments passed to the ``i18n.translate`` constructor if ``value`` is a string.
    :return: An ``i18n.translate`` instance if conversion is possible, or ``None`` if ``value`` was ``None``.
    """
    if isinstance(value, i18n.translate):
        return value
    if value is None:
        return None
    return i18n.translate(value, *args, **kwargs)
