"""
Helper for ViUR-core types and behavior
"""

import logging

from viur.core import current
from viur.core.skeleton import SkeletonInstance, skeletonByKind

__all__ = [
    "change_language",
    "without_render_preparation",
    "get_full_skel_from_ref_skel",
]

logger = logging.getLogger(__name__)


def change_language(lang: str) -> None:
    """Change the current language"""
    current.session.get()["lang"] = lang
    current.language.set(lang)


def without_render_preparation(skel: SkeletonInstance) -> SkeletonInstance:
    """Remove clones skel without render preparation if was set else the skel as is"""
    if skel.renderPreparation is not None:
        # TODO: ViUR, I DONT WANT TO HAVE RENDERPREPARATION ON MODULE LAYER!!!
        skel = skel.clone()
        skel.renderPreparation = None
    return skel


def get_full_skel_from_ref_skel(ref_skel: SkeletonInstance) -> SkeletonInstance:
    kind_name = ref_skel.skeletonCls.__name__.removeprefix("RefSkelFor")
    skel = skeletonByKind(kind_name)()
    skel.fromDB(ref_skel["key"])
    return skel
