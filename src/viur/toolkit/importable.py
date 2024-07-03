import logging
import base64
import typing as t
from google.cloud.datastore import _app_engine_key_pb2
from viur.core import conf, current, db, email, errors, utils
from viur.core.decorators import exposed
from viur.core.skeleton import SkeletonInstance
from viur.core.tasks import CallDeferred
from ..config import CONFIG
from ..importer import Importer


class AppKey(db.Key):
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

    The module then requires for a *importConf* to be defined (see below) and provides several functions for triggering
    and maintenance. The prototype is used in combination with the importer module from the root.
    """

    importConf = {
        "portal": None,  # Importer source portal (from conf["interfaces"]["import"])
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
    }
    _tr = None  # the final translation table once created by create_config()

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
            logging.exception("Cant convert key")
            return 0

        # JMM 2024-05-02:
        # I commented out the stuff below, because the translate_key function
        # should be as universal as possible. If you want another behavior in your
        # importer, feel free to copy and modify it on your demands.

        # name = key.id_or_name
        # if name == key.kind:  # this is a special-case on SubSkelDefinition
        #     name = skel.kindName

        # # TODO: this is kind hackish
        # if "modul_repo" in name:  # add the e for English
        #     name = name.replace("modul_repo", "module_repo")

        # # use skel.kindName as this may change in the target
        # if not kindname:  #  JMM 2024-05-02: was a parameter to the function which is ALWAYS None... makes no sense.
        #     kindname = skel.kindName
        # key = db.Key(kindname, name, parent=None)

        if skel[bone] != key:
            skel[bone] = key
            return 1

        return 0

    def get_handler(self):
        admin_info = self.describe()
        assert (handler := admin_info.get("handler"))
        return handler.split(".", 1)[0]

    def importSkel(self, skelType=None):
        handler = self.get_handler()

        if handler in ["hierarchy", "tree"]:
            try:
                return self.editSkel(skelType=skelType)
            except:
                pass
        return self.editSkel()

    @exposed
    def start_import(
        self,
        follow: bool = False,
        enforce: bool = False,
        inform: str = None,
        dry_run: bool = False,
        otp=None,
        debug: bool = False,
        *args,
        **kwargs,
    ):
        cuser = current.user.get()
        if not cuser or "root" not in cuser["access"]:
            raise errors.Unauthorized()

        # Additional credentials
        creds = {}

        import_conf = (
            self.importConf() if callable(self.importConf) else self.importConf
        )

        cfg = self.get_interface_config()["import"][import_conf.get("portal")]
        if cfg["type"] == "viur" and cfg["auth"] == "userpassword+otp":
            # Hint for OTP
            if not otp:
                raise errors.BadRequest("Requires 'otp' key to succeed")

            creds["otp"] = otp

        if self.get_handler() == "tree" and "skelType" not in kwargs:
            kwargs["skelType"] = "node"
            kwargs["_autoSkelType"] = True

        if not inform:
            inform = import_conf.get("inform", False)
            inform = inform if isinstance(inform, str) else cuser["name"] if inform else None

        self.do_import(
            inform=inform,
            follow=follow,
            enforce=enforce,
            dry_run=dry_run,
            creds=creds or None,
            debug=debug,
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
        importConf: str = "importConf",
        dry_run=False,
        cookies=None,
        creds=None,
        delete_filter=None,
        debug: bool = False,
        **kwargs,
    ):
        import_conf_name = importConf  # backup
        importConf = getattr(self, import_conf_name)
        importConf = importConf() if callable(importConf) else importConf

        assert importConf.get("portal"), "No portal specified to import from"

        # Mark this request as an import task
        current.request.get().kwargs["isImportTask"] = True
        if importdate is None:
            importdate = utils.utcNow().replace(
                microsecond=0
            )  # need to remove microseconds!!!

        logging.debug("module = %r", self.moduleName)
        logging.debug("importdate = %r", importdate)
        logging.debug("total = %d", total)

        # Login
        imp = Importer(
            importConf.get("portal"),
            render=importConf.get("render", "vi"),
            creds=creds,
            cookies=cookies,
        )

        # In case of a hierarchy, always assume skelType "node"
        handler = self.get_handler()
        if handler == "hierarchy":
            kwargs["skelType"] = "node"
        elif handler == "tree":
            if "skelType" not in kwargs:
                raise ValueError("kwargs __must__ contain skelType in case of a tree")

        if not kwargs:
            params = {}
        else:
            params = kwargs.copy()

        if conf_params := importConf.get("params"):
            if callable(conf_params):
                conf_params = conf_params(cursor)

            assert isinstance(
                params, dict
            ), "importConf[\"params\"] must be either 'dict' or 'callable' returning dict"
            params.update(conf_params)

        if "limit" not in params:
            params["limit"] = importConf.get("limit", 99)
            params["amount"] = importConf.get("limit", 99)
        params["limit"] = params["amount"] = 30
        if "cursor" not in params:
            params["cursor"] = cursor

        url = (
            f"{importConf.get('module', self.moduleName)}/{importConf.get('action', 'list')}"
        )
        answ = imp.post(url, params=params, timeout=60)

        if not answ.ok:
            logging.error(
                "Cannot fetch list from %r, error %d occured", url, answ.status_code
            )
            raise errors.BadRequest()

        try:
            answ = answ.json()

        except:
            logging.warning(
                "Target module %r does not exist in source or some other error occured - skipping",
                importConf.get("module", self.moduleName),
            )
            self._kickoff_follow(importdate, inform, **kwargs)
            return

        # Get skeleton
        skel = self.importSkel(skelType=kwargs.get("skelType"))

        self.create_config(skel)

        # Perform import
        if isinstance(answ, dict):
            skellist = answ.get("skellist")
            cursor = answ.get("cursor")
        elif isinstance(answ, list):
            skellist = answ

        for values in skellist:
            total += 1

            if "skip" in importConf and importConf["skip"](values):
                continue

            # logging.debug(f"{values=}")

            if self._convert_entry(
                imp,
                skel,
                values,
                importdate,
                skel_type=kwargs.get("skelType"),
                enforce=enforce,
                dry_run=dry_run,
                updateRelations=importConf.get("updateRelations", True),
                debug=debug,
            ):
                updated += 1

                # if total >= 5:
                #    skellist = ()
                #    break

        logging.info("%s: %d entries imported, %d entries updated", self.moduleName, total, updated)

        if not skellist or cursor is None:
            imp.logout()  # log-out now, as we're finished reading

            # Clear deleted entries?
            if "importdate" in skel:
                self.do_clear(
                    importdate,
                    inform,
                    total,
                    updated,
                    importConf=import_conf_name,
                    follow=follow,
                    dry_run=dry_run,
                    _queue="import",
                    delete_filter=delete_filter,
                    **kwargs,
                )
                return

            logging.info(
                "%s: Import finished; %d entries in total, %d updated",
                self.moduleName,
                total,
                updated,
            )

            if inform:
                email.sendEMail(
                    dests=inform,
                    tpl="import_finished",
                    skel={
                        "sourceportal": importConf.get("portal"),
                        "targetportal": conf.instance.project_id.replace(
                            "-viur", ""
                        ),
                        "sourcemodule": importConf.get("module", self.moduleName),
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
            importConf=import_conf_name,
            inform=inform,
            spawn=spawn + 1,
            cursor=cursor,
            total=total,
            updated=updated,
            follow=follow,
            _queue="import",
            dry_run=dry_run,
            cookies=imp.cookies.get_dict(),
            delete_filter=delete_filter,
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

    def create_config(self, skel):
        importConf = self.importConf() if callable(self.importConf) else self.importConf

        # Get translation from config
        tr = importConf.get("translate")

        # If it's a 1-to-1 list, make it a dict.
        if isinstance(tr, list):
            tr = {k: k for k in tr}

        # Otherwise, when not specified, automatically construct a translation from the skeleton with some specials
        elif tr is None:
            tr = self.import_generate_translation(skel)

        # update further bones to (probably automatic) translation
        tr |= importConf.get("translate.update") or {}

        # Remove any bones that should be ignored
        for k in list(tr.keys()):
            if k in ["key", "changedate", "importdate"] + (
                importConf.get("translate.ignore") or []
            ):
                del tr[k]

        assert isinstance(tr, dict), "translation must be specified as dict!"
        self._tr = tr

    def do_import_entry(
        self, key, importConf=None, module=None, kindName=None, skel_type="node",
        debug: bool = False,
    ):
        if not importConf:
            importConf = (
                self.importConf() if callable(self.importConf) else self.importConf
            )

        importdate = utils.utcNow()

        # Login
        try:
            imp = Importer(
                importConf.get("portal"), render=importConf.get("render", "vi")
            )

        except Exception as e:
            logging.exception(e)
            return

        skel = self.importSkel(skelType=skel_type)

        self.create_config(skel)

        key = db.KeyClass.from_legacy_urlsafe(key)

        if not kindName:
            kindName = importConf.get("module")

        key = AppKey(kindName, key.id_or_name)

        assert (
            project_id := self.get_interface_config()["import"]
            .get(importConf.get("portal"), {})
            .get("project_id")
        ), f"Please set the projectid of the portal {importConf.get('portal')}"
        key = key.to_legacy_urlsafe(project_id=project_id).decode("utf-8")

        if not module:
            module = importConf.get("module", self.moduleName)
        url = f"{module}/view/{key}"

        answ = imp.post(url, timeout=60)
        if not answ.ok:
            logging.error(
                "Cannot fetch list from %r, error %d occured", url, answ.status_code
            )
            raise errors.BadRequest()

        try:
            answ = answ.json()
        except:
            logging.warning(
                "Target module %r does not exist in source or some other error occured - skipping",
                importConf.get("module", self.moduleName),
            )
            return
        values = answ["values"]

        return self._convert_entry(
            imp,
            skel,
            values,
            importdate,
            skel_type,
            enforce=importConf.get("enforce", False),
            updateRelations=importConf.get("updateRelations", True),
            debug=debug,
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
    ):
        """
        Internal function for converting one entry.
        """
        skel.setEntity(db.Entity())
        ret = imp.toSkel(
            skel,
            values,
            self._tr,
            sourceKey="key" if "key" in values else "id",
            enforce=enforce,
            debug=debug,
        )

        if "outdated" in skel:
            skel["outdated"] = False

        if dry_run:
            logging.info(f"dry run {ret=}, {skel=}")
            return ret != 0

        if ret != 0 or enforce:
            if not self.onEntryChanged(skel, values):
                return False

            # Set importdate when available
            if "importdate" in skel:
                logging.debug(
                    "%s: Setting importdate on %r to %r",
                    self.moduleName,
                    skel["key"],
                    importdate,
                )
                skel["importdate"] = importdate
            try:
                assert skel.toDB(update_relations=updateRelations)
            except Exception as e:
                logging.error(f"cannot convert {skel['key']}    {skel!r}")
                raise e

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

    def _kickoff_follow(self, importdate, inform, **kwargs):
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

        importConf = self.importConf() if callable(self.importConf) else self.importConf

        for name in importConf.get("follow") or []:
            # mod = getattr(conf.main_app, name, None)
            mod = getattr(conf.main_app.vi, name, None)
            if mod and isinstance(mod, Importable):
                logging.info("%s: Kicking off import for %r", self.moduleName, name)
                mod.do_import(importdate, inform=inform, follow=True, _queue="import")
            else:
                logging.warning("Cannot follow module '%r'", name)

    @CallDeferred
    def do_clear(
        self,
        importdate,
        inform,
        total,
        updated,
        importConf=None,
        cursor=None,
        removed=0,
        follow=False,
        dry_run=False,
        delete_filter=None,
        **kwargs,
    ):
        logging.info("do_clear")
        _importConfName = importConf
        if importConf:
            _importConf = getattr(self, importConf)
            importConf = _importConf() if callable(_importConf) else _importConf
        else:
            importConf = (
                self.importConf() if callable(self.importConf) else self.importConf
            )

        assert importConf.get("portal"), "No portal specified to import from"

        # Mark this request as an import task
        current.request.get().kwargs["isImportTask"] = True

        # Get skeleton
        skel = self.importSkel(skelType=kwargs.get("skelType"))
        assert skel

        q = skel.all()

        if not delete_filter:
            delete_filter = {}

        if conf_filter := importConf.get("filter"):
            delete_filter.update(conf_filter)

        q.filter("importdate <", importdate)
        q = q.mergeExternalFilter(delete_filter)

        # q = self.listFilter(q)
        if not q:
            logging.error("filter prohibits clearing")
            return

        if cursor:
            q.setCursor(cursor)

        fetched = 0
        for skel in q.fetch(limit=99):
            logging.debug(
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
                    logging.info(f"dry run outdating {skel=}")
                    continue

                skel.toDB()
            else:
                if dry_run:
                    logging.info(f"dry run deleting {skel=}")
                    continue

                skel.delete()

                if self.get_handler() in ["hierarchy", "tree"]:
                    self.onDeleted(kwargs["skelType"], skel)
                else:
                    self.onDeleted(skel)

            fetched += 1
            removed += 1

        logging.info(
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
                importConf=_importConfName,
                follow=follow,
                _queue="import",
                delete_filter=delete_filter,
                **kwargs,
            )
            return

        logging.info(
            "%s: Import finished, %d entries in total, %d updated, %d deleted",
            self.moduleName,
            total,
            updated,
            removed,
        )

        if inform:  # No email
            email.sendEMail(
                dests=inform,
                tpl="import_finished",
                skel={
                    "sourceportal": importConf.get("portal"),
                    "targetportal": conf.instance.project_id.replace(
                        "-viur", ""
                    ),
                    "sourcemodule": importConf.get("module", self.moduleName),
                    "targetmodule": self.moduleName,
                    "total": total,
                    "updated": updated,
                    "removed": removed,
                },
            )

        self.onImportFinished(self.moduleName, total, updated, **kwargs)

        if follow:
            self._kickoff_follow(importdate, inform, **kwargs)

    _interface_config = None

    @classmethod
    # @property
    def get_interface_config(cls) -> dict:
        if Importable._interface_config is None:
            # default value
            return CONFIG.interfaces
        return Importable._interface_config

    @classmethod
    # @interface_config.setter
    def set_interface_config(cls, value: dict) -> None:
        Importable._interface_config = value


def rewrite_select_options(skel, bone_name, value, match):
    is_list = True
    if not isinstance(value, list):
        value = [value]
        is_list = False

    changes = 0
    new_value = []
    for val in value:
        if val in match:
            val = match[val]
        new_value.append(val)

    if not skel[bone_name] or set(skel[bone_name]) != set(new_value):
        if not is_list:
            skel.setBoneValue(bone_name, new_value[0])
        else:
            skel.setBoneValue(bone_name, new_value)
        changes += 1

    return changes
