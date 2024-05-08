"""
Helper for ViUR-core types and behavior
"""

import logging
import typing as t

from viur.core import current, db
from viur.core.skeleton import SkeletonInstance, skeletonByKind

__all__ = [
    "change_language",
    "get_task_retry_count",
    "without_render_preparation",
    "get_full_skel_from_ref_skel",
    "iter_skel",
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


def without_render_preparation(skel: SkeletonInstance) -> SkeletonInstance:
    """Remove clones skel without render preparation if was set else the skel as is"""
    if skel.renderPreparation is not None:
        # TODO: ViUR, I DONT WANT TO HAVE RENDERPREPARATION ON MODULE LAYER!!!
        skel = skel.clone()
        skel.renderPreparation = None
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
        try:
            yield skel
        except GeneratorExit:
            logger.warning("GeneratorExit. Stop iteration.")
            break
