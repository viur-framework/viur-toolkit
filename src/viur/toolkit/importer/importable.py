"""
`Importable` is a prototype that can be attached to any ViUR module to provide a configurable
and and hookable interface for executing imports, partly automatically.
"""

import base64
import logging
import time
import typing as t

from google.cloud.datastore import _app_engine_key_pb2

from viur.core import conf, current, db, email, errors, utils
from viur.core.decorators import exposed
from viur.core.skeleton import SkeletonInstance
from viur.core.tasks import CallDeferred
from .importer import Importer

logger = logging.getLogger(__name__)

JINJA_EMAIL_TEMPLATE = """{{ skel["targetportal"] }}.{{ skel["targetmodule"] }} import done, total:{{ skel["total"]}}, updated:{{ skel["updated"]}}, removed:{{ skel["removed"]}}
<!DOCTYPE html>
<html lang="de">
<body>
    Der Import von {{ skel["sourceportal"] }}.{{ skel["sourcemodule"] }}
    nach {{ skel["targetportal"] }}.{{ skel["targetmodule"] }} wurde erfolgreich durchgeführt.<br>

    Es wurden {{ skel["total"]}} Datensätze geprüft, davon {{ skel["updated"] }} aktualisiert.<br>
    {{ skel["removed"] }} Datensätze wurden gelöscht.
</body>
</html>"""


class _AppKey(db.Key):
    def to_legacy_urlsafe(self, project_id=None) -> str:
        """
        Converts this key into the (urlsafe) protobuf string representation.
        :return: The urlsafe string representation of this key
        """
        currentKey = self
        pathElements = []
        while currentKey:
            pathElements.insert(
                0,
                _app_engine_key_pb2.Path.Element(
                    type=currentKey.kind,
                    id=currentKey.id,
                    name=currentKey.name,
                ),
            )
            currentKey = self.parent

        if not project_id:
            project_id = conf.project_id

        reference = _app_engine_key_pb2.Reference(
            app=project_id,
            path=_app_engine_key_pb2.Path(element=pathElements),
        )
        raw_bytes = reference.SerializeToString()
        return base64.urlsafe_b64encode(raw_bytes).strip(b"=")


class Importable:
    """
    Importable prototype

    This prototype can be attached to any module making it importable. Data imports can both be done between ViUR2
    and ViUR3 systems. Only the JSON interface is used.

    The module then requires for a *import_conf* to be defined (see below) and provides several functions for triggering
    and maintenance. The prototype is used in combination with the importer module from the root.
    """

    # !!!TODO!!! Should be turned into a class!
    import_conf = {
        "source": {
            "url": None,  # this is mandatory!
            "auth": "viur",  # It can also be other sources used
            "method": "userpassword"  # TODO: Document all types
        },
        "module": None,  # Source module; if None, same name as the importable module will be used.
        "translate": None,  # Translation dictionary; if omitted, it will be generated from bone:bone
        "translate.update": None,  # Translation dictionary; extend and automatically generated one (if translate==None)
        "translate.ignore": None,  # Bones to be ignored in automatically generated translation
        "action": "list",  # Action to run, default is "list"
        "limit": 99,  # Amount of items to fetch per request (only for list-ables)
        "render": "vi",  # Renderer to run on
        "params": None,  # Further parameters passed to the action
        "follow": [],  # Following modules to be imported, that depend on this import.
        "filter": {},  # Define a custom filter to be used for preparation and cleaning
        "updateRelations": True,  # Allows to disable update relation tasks enforcements when configured to False.
        "enforce": False,  # Enforce all full skeletons to be rewritten.
        "skip": lambda values: False,  # don't skip any entry by default
        "inform": False,  # either an e-mail address to inform, or True for current user, False otherwise.
        "clear": True,  # Do do_clear and delete not imported entries
    }
    _bone_translation_table = {}  # the final translation table once created by create_config()

    def modify_skel_key(
        self,
        key: db.Key,
        skel: SkeletonInstance,
        values: dict[str, t.Any],
        translate: dict[str, str | t.Callable],
        source_key: str,
    ) -> db.Key:
        return key

    @staticmethod
    def translate_key(skel, bone, value, **_):
        """
        Helper function to replace a key during translation, even if its not a keyBone.
        """
        if not value:
            return 0
        try:
            key = db.Key.from_legacy_urlsafe(value)
            assert not key.parent, "Not implemented"
        except:
            logger.exception("Can't convert key")
            return 0

        if skel[bone] != key:
            skel[bone] = key
            return 1

        return 0

    @staticmethod
    def translate_select_values(skel, bone_name, value, matching):
        """
        Helper to rewrite select values from a given matching table.
        """
        is_list = True
        if not isinstance(value, list):
            value = [value]
            is_list = False

        changes = 0
        new_value = []

        for val in value:
            if val in matching:
                val = matching[val]
            new_value.append(val)

        if not skel[bone_name] or set(skel[bone_name]) != set(new_value):
            if not is_list:
                skel.setBoneValue(bone_name, new_value[0])
            else:
                skel.setBoneValue(bone_name, new_value)

            changes += 1

        return changes

    def get_handler(self):
        admin_info = self.describe()
        assert (handler := admin_info.get("handler"))
        return handler.split(".", 1)[0]

    def import_skel(self, skelType=None):
        handler = self.get_handler()

        if handler == "tree":
            try:
                return self.editSkel(skelType=skelType)
            except:
                pass

        return self.editSkel()

    @exposed
    def start_import(
        self,
        *,
        follow: bool = False,
        enforce: bool = False,
        inform: str = "false",
        dry_run: bool = False,
        otp=None,
        debug: bool = False,
        import_conf_name: str = "import_conf",
        **kwargs,
    ):
        cuser = current.user.get()
        if not cuser or "root" not in cuser["access"]:
            raise errors.Unauthorized()

        # Additional credentials
        import_conf = getattr(self, import_conf_name)
        import_conf = import_conf() if callable(import_conf) else import_conf

        source = import_conf.get("source") or {}

        if source.get("type") == "viur" and source.get("auth") == "userpassword+otp":
            # Hint for OTP
            if not otp:
                raise errors.BadRequest("Requires 'otp' key to succeed")

            source["otp"] = otp

        if self.get_handler() == "tree":
            kwargs.setdefault("skelType", "node")
            kwargs.setdefault("_autoSkelType", True)

        if "@" not in inform:
            inform = utils.parse.bool(inform)
            inform = import_conf.get("inform") or inform

        inform = inform if isinstance(inform, str) else cuser["name"] if inform else None

        self.do_import(
            inform=inform,
            follow=follow,
            enforce=enforce,
            dry_run=dry_run,
            source=source or None,
            debug=debug,
            import_conf_name=import_conf_name,
            _queue="import",
            **kwargs,
        )

        info = f"Import of {self.moduleName} kicked off"
        if inform:
            info += f", {inform} will be notified by e-mail on finish"

        return info

    @CallDeferred
    def do_import(
        self,
        importdate=None,
        inform=None,
        spawn=0,
        cursor=None,
        total=0,
        updated=0,
        follow=False,
        enforce=False,
        dry_run=False,
        cookies=None,
        source=None,
        delete_filter=None,
        debug: bool = False,
        import_conf_name: str = "import_conf",
        **kwargs,
    ):
        import_conf = getattr(self, import_conf_name)
        import_conf = import_conf() if callable(import_conf) else import_conf
        assert import_conf.get("source"), "No source specified to import from"

        # Mark this request as an import task
        current.request.get().kwargs["isImportTask"] = True  # FIXME!
        if importdate is None:
            importdate = utils.utcNow().replace(microsecond=0)  # need to remove microseconds!!!

        logger.debug(f"{self.moduleName!r} {importdate=} {total=}")

        # Login
        imp = Importer(
            import_conf.get("source") or {} | source or {},
            render=import_conf.get("render", "vi"),
            cookies=cookies,
        )

        # In case of a hierarchy, always assume skelType "node"
        handler = self.get_handler()
        if handler == "tree":
            kwargs.setdefault("skelType", "node")

        if not kwargs:
            params = {}
        else:
            params = kwargs.copy()

        if conf_params := import_conf.get("params"):
            if callable(conf_params):
                conf_params = conf_params(cursor)

            assert isinstance(
                params, dict
            ), "import_conf[\"params\"] must be either 'dict' or 'callable' returning dict"
            params.update(conf_params)

        if "limit" not in params:
            params["limit"] = import_conf.get("limit", 99)
            params["amount"] = import_conf.get("limit", 99)

        if "cursor" not in params:
            params["cursor"] = cursor

        url = f"""{import_conf.get("module", self.moduleName)}/{import_conf.get("action", "list")}"""
        answ = imp.post(url, params=params, timeout=60)

        if not answ.ok:
            logger.error(f"Cannot fetch list from {url=}, {answ.status_code=}")
            raise errors.BadRequest()

        try:
            answ = answ.json()

        except:
            logger.warning(
                "Target module %r does not exist in source or some other error occured - skipping",
                import_conf.get("module", self.moduleName),
            )
            self._kickoff_follow(importdate, inform, import_conf_name=import_conf_name, **kwargs)
            return

        # Get skeleton
        skel = self.import_skel(skelType=kwargs.get("skelType"))

        self.create_config(skel)

        # Perform import
        if isinstance(answ, dict):
            skellist = answ.get("skellist")
            cursor = answ.get("cursor")
        elif isinstance(answ, list):
            skellist = answ

        for values in skellist:
            total += 1

            if "skip" in import_conf and import_conf["skip"](values):
                continue

            # logger.debug(f"{values=}")

            if self._convert_entry(
                imp,
                skel,
                values,
                importdate,
                skel_type=kwargs.get("skelType"),
                enforce=enforce,
                dry_run=dry_run,
                updateRelations=import_conf.get("update_relations", True),
                debug=debug,
                import_conf_name=import_conf_name,
            ):
                updated += 1

                # if total >= 5:
                #    skellist = ()
                #    break

        logger.info("%s: %d entries imported, %d entries updated", self.moduleName, total, updated)

        if not skellist or cursor is None:
            imp.logout()  # log-out now, as we're finished reading

            # Clear deleted entries?
            if import_conf.get("clear", True) and "importdate" in skel:
                self.do_clear(
                    importdate,
                    inform,
                    total,
                    updated,
                    follow=follow,
                    dry_run=dry_run,
                    delete_filter=delete_filter,
                    import_conf_name=import_conf_name,
                    _queue="import",
                    **kwargs,
                )
                return

            logger.info(
                "%s: Import finished; %d entries in total, %d updated",
                self.moduleName,
                total,
                updated,
            )

            if inform:
                email.sendEMail(
                    dests=inform,
                    stringTemplate=JINJA_EMAIL_TEMPLATE,
                    skel={
                        "sourceportal": import_conf["source"]["url"],
                        "targetportal": conf.instance.project_id.replace(
                            "-viur", ""
                        ),
                        "sourcemodule": import_conf.get("module", self.moduleName),
                        "targetmodule": self.moduleName,
                        "total": total,
                        "updated": updated,
                        "removed": 0,
                    },
                )

            self.onImportFinished(self.moduleName, total, updated)

            if follow:
                self._kickoff_follow(importdate, inform, **kwargs)

            return True

        self.do_import(
            importdate=importdate,
            inform=inform,
            spawn=spawn + 1,
            cursor=cursor,
            total=total,
            updated=updated,
            follow=follow,
            dry_run=dry_run,
            cookies=imp.cookies.get_dict(),
            delete_filter=delete_filter,
            import_conf_name=import_conf_name,
            _queue="import",
            **kwargs,
        )

        return True

    def import_generate_translation(self, skel: SkeletonInstance) -> dict[str, t.Any]:
        """
        Automatically generates a 1-to-1 translation from the given skel.
        Can be subclasses for custom behavior.
        """
        tr = {k: k for k in skel.keys()}

        if "parentrepo" in skel:
            tr["parentrepo"] = Importable.translate_key

        if "parententry" in skel:
            tr["parententry"] = Importable.translate_key

            # ViUR2 legacy bullshit, in trees parententry was called parentdir...
            tr["parentdir"] = lambda bone, **kwargs: Importable.translate_key(
                bone="parententry", **kwargs
            )

        return tr

    def create_config(self, skel: SkeletonInstance, import_conf_name: str = "import_conf") -> None:
        import_conf = getattr(self, import_conf_name)
        import_conf = import_conf() if callable(import_conf) else import_conf

        # Get translation from config
        tr = import_conf.get("translate")

        # If it's a 1-to-1 list, make it a dict.
        if isinstance(tr, list):
            tr = {k: k for k in tr}

        # Otherwise, when not specified, automatically construct a translation from the skeleton with some specials
        elif tr is None:
            tr = self.import_generate_translation(skel)

        # update further bones to (probably automatic) translation
        tr |= import_conf.get("translate.update") or {}

        # Remove any bones that should be ignored
        for k in list(tr.keys()):
            if k in ["key", "changedate", "importdate"] + (
                import_conf.get("translate.ignore") or []
            ):
                del tr[k]

        assert isinstance(tr, dict), "translation must be specified as dict!"
        self._bone_translation_table[import_conf_name] = tr

    def do_import_entry(
        self, key, module=None, kindName=None, skel_type="node",
        debug: bool = False,
        import_conf_name: str = "import_conf",
    ):
        import_conf = getattr(self, import_conf_name)
        import_conf = import_conf() if callable(import_conf) else import_conf

        importdate = utils.utcNow()

        # Login
        try:
            imp = Importer(
                source=import_conf.get("source") or {},
                render=import_conf.get("render", "vi")
            )

        except Exception as e:
            logger.exception(e)
            return

        skel = self.import_skel(skelType=skel_type)

        self.create_config(skel, import_conf_name=import_conf_name)

        key = db.KeyClass.from_legacy_urlsafe(key)

        if not kindName:
            kindName = import_conf.get("module")

        key = _AppKey(kindName, key.id_or_name)

        project_id = import_conf.get("project_id")
        assert project_id, f"Please set the project_id of portal {import_conf.get('url')}"
        key = key.to_legacy_urlsafe(project_id=project_id).decode("utf-8")

        if not module:
            module = import_conf.get("module", self.moduleName)
        url = f"{module}/view/{key}"

        answ = imp.post(url, timeout=60)
        if not answ.ok:
            logger.error(
                "Cannot fetch list from %r, error %d occured", url, answ.status_code
            )
            raise errors.BadRequest()

        try:
            answ = answ.json()
        except:
            logger.warning(
                "Target module %r does not exist in source or some other error occured - skipping",
                import_conf.get("module", self.moduleName),
            )
            return
        values = answ["values"]

        return self._convert_entry(
            imp,
            skel,
            values,
            importdate,
            skel_type,
            enforce=import_conf.get("enforce", False),
            updateRelations=import_conf.get("updateRelations", True),
            debug=debug,
            import_conf_name=import_conf_name,
        )

    def _convert_entry(
        self,
        imp,
        skel,
        values,
        importdate,
        skel_type=None,
        enforce=False,
        dry_run=False,
        updateRelations=True,
        debug: bool = False,
        import_conf_name: str = "import_conf",
    ):
        """
        Internal function for converting one entry.
        """
        skel.setEntity(db.Entity())
        ret = imp.values_to_skel(
            skel,
            values,
            self._bone_translation_table,
            source_key="key" if "key" in values else "id",  # ViUR 1.x
            enforce=enforce,
            debug=debug,
        )

        if "outdated" in skel:
            skel["outdated"] = False

        if dry_run:
            logger.info(f"dry run {ret=}, {skel=}")
            return ret != 0

        if ret != 0 or enforce:
            if not self.onEntryChanged(skel, values):
                return False

            # Set importdate when available
            if "importdate" in skel:
                logger.debug(
                    "%s: Setting importdate on %r to %r",
                    self.moduleName,
                    skel["key"],
                    importdate,
                )
                skel["importdate"] = importdate

            for attempt in (rng := range(3)):  # TODO: Make it configureable
                try:
                    assert skel.toDB(update_relations=updateRelations)
                except Exception as e:
                    logger.exception(f"cannot convert {skel['key']} : {e!s}   {skel!r}")

                    if attempt == rng.stop - rng.step:
                        raise e

                    logger.info(f"Waiting {2 ** attempt} seconds for the next attempt")
                    time.sleep(2 ** attempt)

                else:
                    break

            handler = self.get_handler()

            if handler in ["hierarchy", "tree"]:
                if ret < 0:
                    self.onAdded(skel_type, skel)
                else:
                    self.onEdited(skel_type, skel)
            else:
                if ret < 0:
                    self.onAdded(skel)
                else:
                    self.onEdited(skel)

            return True
        else:
            if not self.onEntryUnchanged(skel, values):
                return False

            # Save with importdate when required
            if "importdate" in skel:
                skel["importdate"] = importdate

                assert skel.toDB(update_relations=True)
        return False

    def onEntryChanged(self, skel, values):
        return True

    def onEntryUnchanged(self, skel, values):
        return True

    def onImportFinished(self, moduleName, total, updated, **kwargs):
        pass

    def _kickoff_follow(self, importdate, inform, import_conf_name: str = "import_conf", **kwargs):
        # Check if tree type and nodes where imported, then import the leafs first
        if (
            self.get_handler() == "tree"
            and kwargs.get("skelType") == "node"
            and kwargs.get("_autoSkelType")
        ):
            kwargs["skelType"] = "leaf"
            kwargs["_autoSkelType"] = True
            self.do_import(importdate, inform, follow=True, **kwargs)
            return

        import_conf = getattr(self, import_conf_name)
        import_conf = import_conf() if callable(import_conf) else import_conf

        for name in import_conf.get("follow") or []:
            # mod = getattr(conf.main_app, name, None)
            mod = getattr(conf.main_app.vi, name, None)
            if mod and isinstance(mod, Importable):
                logger.info("%s: Kicking off import for %r", self.moduleName, name)
                mod.do_import(importdate, inform=inform, follow=True, _queue="import")
            else:
                logger.warning("Cannot follow module '%r'", name)

    @CallDeferred
    def do_clear(
        self,
        importdate,
        inform,
        total,
        updated,
        import_conf_name: str = "import_conf",
        cursor=None,
        removed=0,
        follow=False,
        dry_run=False,
        delete_filter=None,
        **kwargs,
    ):
        logger.info("do_clear")
        import_conf = getattr(self, import_conf_name)
        import_conf = import_conf() if callable(import_conf) else import_conf

        assert import_conf.get("source"), "No source specified to import from"

        # Mark this request as an import task
        current.request.get().kwargs["isImportTask"] = True

        # Get skeleton
        skel = self.import_skel(skelType=kwargs.get("skelType"))
        assert skel

        q = skel.all()

        if not delete_filter:
            delete_filter = {}

        if conf_filter := import_conf.get("filter"):
            delete_filter.update(conf_filter)

        q.filter("importdate <", importdate)
        q = q.mergeExternalFilter(delete_filter)

        if not q:
            logger.error("filter prohibits clearing")
            return

        if cursor:
            q.setCursor(cursor)

        fetched = 0
        for skel in q.fetch(limit=99):
            logger.debug(
                "%s: Deleting %r with importdate %r",
                self.moduleName,
                skel["key"],
                skel["importdate"],
            )

            if "import_behavior" in skel and skel["import_behavior"] in [
                "only_override",
                "keep",
            ]:
                continue  # don't remove this marked entries

            if "outdated" in skel:
                skel["outdated"] = True

                if dry_run:
                    logger.info(f"dry run outdating {skel=}")
                    continue

                skel.toDB()
            else:
                if dry_run:
                    logger.info(f"dry run deleting {skel=}")
                    continue

                skel.delete()

                if self.get_handler() in ["hierarchy", "tree"]:
                    self.onDeleted(kwargs["skelType"], skel)
                else:
                    self.onDeleted(skel)

            fetched += 1
            removed += 1

        logger.info(
            "%s: %d entries %s",
            self.moduleName,
            fetched,
            "flagged outdated" if "outdated" in skel else "deleted",
        )

        if fetched and (cursor := q.getCursor()):
            self.do_clear(
                importdate,
                inform,
                total,
                updated,
                cursor=cursor,
                removed=removed,
                import_conf_name=import_conf_name,
                follow=follow,
                delete_filter=delete_filter,
                _queue="import",
                **kwargs,
            )
            return

        logger.info(
            "%s: Import finished, %d entries in total, %d updated, %d deleted",
            self.moduleName,
            total,
            updated,
            removed,
        )

        if inform:
            email.sendEMail(
                dests=inform,
                stringTemplate=JINJA_EMAIL_TEMPLATE,
                skel={
                    "sourceportal": import_conf["source"]["url"],
                    "targetportal": conf.instance.project_id.replace(
                        "-viur", ""
                    ),
                    "sourcemodule": import_conf.get("module", self.moduleName),
                    "targetmodule": self.moduleName,
                    "total": total,
                    "updated": updated,
                    "removed": removed,
                },
            )

        self.onImportFinished(self.moduleName, total, updated, **kwargs)

        if follow:
            self._kickoff_follow(importdate, inform, **kwargs)
