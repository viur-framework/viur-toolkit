"""Callable tasks (tasks which can be called by a user from vi-admin)"""
import logging
import typing as t

from viur.core import conf, current, email, translate
from viur.core.bones import FileBone, SelectBone
from viur.core.bones.file import ensureDerived
from viur.core.skeleton import BaseSkeleton, SkeletonInstance, listKnownSkeletons, skeletonByKind
from viur.core.tasks import CallableTask, CallableTaskBase, QueryIter
from .checks import user_has_access

__all__ = [
    "BuildDerivationsDispatcher",
    "BuildDerivations",
]

logger = logging.getLogger(__name__)

_CustomDataType = t.TypedDict("_CustomDataType", {
    "notify": str | None,
    "module": str,
})


@CallableTask
class BuildDerivationsDispatcher(CallableTaskBase):
    """
    This tasks dispatches BuildDerivations with a given module.
    """
    key = "build_derivations"
    name = "Build Derivation"
    descr = "This task can be called to build missing derivations."

    def canCall(self) -> bool:
        """Checks wherever the current user can execute this task"""
        return user_has_access("root")

    def dataSkel(self) -> BaseSkeleton:
        modules = ["*"] + listKnownSkeletons()
        modules.sort()
        skel = BaseSkeleton().clone()
        skel.module = SelectBone(descr="Module", values={x: translate(x) for x in modules}, required=True)
        return skel

    def execute(self, module: str) -> None:
        usr = current.user.get()
        if not usr:
            logger.warning("Don't know who to inform after rebuilding finished")
            notify = None
        else:
            notify = usr["name"]

        if module == "*":
            modules = listKnownSkeletons()
        else:
            modules = [module]
        for module in modules:
            logger.info(f"Rebuilding search index for {module=}")
            self._run(module, notify)

    @staticmethod
    def _run(module: str, notify: str | None) -> None:
        skel_cls = skeletonByKind(module)
        if not skel_cls:
            logger.error(f"{BuildDerivationsDispatcher.__name__}: Invalid {module=}")
            return
        BuildDerivations.startIterOnQuery(skel_cls().all(), {"notify": notify, "module": module})


class BuildDerivations(QueryIter):
    """Task which calls ensureDerived on every FileBone in a Skeleton"""

    @classmethod
    def handleEntry(cls, skel: SkeletonInstance, customData: _CustomDataType) -> None:
        for bone_name, bone_instance in skel.items():
            if not isinstance(bone_instance, FileBone):
                continue
            cls._bone_ensure_derived(skel, bone_instance, bone_name)

    @classmethod
    def _bone_ensure_derived(cls, skel: SkeletonInstance, bone_instance: FileBone, bone_name: str) -> None:
        """Logic from FileBone.postSavedHandler"""

        def handleDerives(values: dict | list) -> None:
            if isinstance(values, dict):
                values = [values]
            for val in values:  # Ensure derives getting build for each file referenced in this relation
                ensureDerived(val["dest"]["key"], f"{skel.kindName}_{bone_name}", bone_instance.derive)

        values = skel[bone_name]
        if bone_instance.derive and values:
            if isinstance(values, dict) and "dest" not in values:  # multi lang
                for lang in values:
                    handleDerives(values[lang])
            else:
                handleDerives(values)

    @classmethod
    def handleFinish(cls, total_count: int, custom_data: _CustomDataType) -> None:
        super().handleFinish(total_count, custom_data)
        if not custom_data["notify"]:
            return
        txt = (
            f"{conf.instance.project_id}: Build derivations finished for {custom_data['module']}\n\n"
            f"ViUR finished to build derivations for module {custom_data['module']}.\n"
            f"{total_count} records updated in total on this kind."
        )
        try:
            email.sendEMail(dests=custom_data["notify"], stringTemplate=txt, skel=None)
        except Exception as exc:  # noqa; OverQuota, whatever
            logger.exception(f'Failed to notify {custom_data["notify"]}')
