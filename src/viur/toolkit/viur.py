from viur.core import current

from viur.core.skeleton import SkeletonInstance

__all__ = ["change_language", "without_render_preparation"]


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
