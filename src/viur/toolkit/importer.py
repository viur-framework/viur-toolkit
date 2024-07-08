"""
Tools for copying data from ViUR 1.x to ViUR 3.x systems by using the JSON interfaces.

The module is split into two parts:

1. `Importer` is a `requests.Session`-inherited class which provides helpers to convert from JSON
   into a skeleton structure.
2. `Importable` is a prototype that can be attached to any ViUR module to provide a configurable
   and and hookable interface for executing imports, partly automatically.
"""
import base64
import html
import json
import logging
import mimetypes
import numbers
import re
import requests
import typing as t
from google.cloud.datastore import _app_engine_key_pb2
from viur.core import bones, conf, current, db, email, errors, utils
from viur.core.decorators import exposed
from viur.core.skeleton import SkeletonInstance
from viur.core.tasks import CallDeferred

logger = logging.getLogger(__name__)


class Importer(requests.Session):

    def __init__(self, source, render="vi", cookies=None):
        super().__init__()

        url = source["url"]
        if not url:
            raise IOError("Importer disabled by configuration")

        self.host = url
        self.render = render
        self.method = source.get("auth")
        self.secretname = self.user = self.password = self.key = self.otp = None

        if cookies:
            logger.info(f"Using existing session cookies {cookies.keys()}")
            self.cookies.update(cookies)
            return

        if self.method == "userpassword":
            self.user = source["user"]
            self.password = source["pass"]
        elif self.method == "userpassword+otp":
            self.user = source["user"]
            self.password = source["pass"]
            self.otp = source["otp"]
        elif self.method in ["secretkey", "loginkey"]:
            self.secretname = source.get("keyname", "secret")

            if module := source.get("from"):
                assert "." in module
                module, key = module.split(".", 1)

                mod = getattr(conf.main_app.vi, module)  # fixme: viur-core 3.7 Remove vi when possibel!
                mod = db.Get(db.Key(mod.viewSkel().kindName, mod.getKey()))
                self.key = mod[key]
            else:
                self.key = source.get("key")

            assert self.key, "No key defined?"

        elif self.method is not None:
            raise ValueError(f"Unsupported authmethod configuration {self.method!r}")

        if self.method and not self.login():
            raise IOError(f"Unable to logon to '{self.host}'")

    def logout(self):
        if self.method != "secretkey":
            return self.get("/user/logout", params={"skey": self.skey()}, timeout=30).json()

    def skey(self):
        return self.get("/skey", timeout=30).json()

    def get(self, url, *args, **kwargs):
        if url.startswith("/"):
            url = url[1:]

        if self.method == "secretkey":
            if "data" not in kwargs:
                kwargs["data"] = {}

            kwargs["data"][self.secretname] = self.key
        else:
            logger.debug(f"GET  {'/'.join([self.host, self.render, url])} {kwargs}")

        return super().get("/".join([self.host, self.render, url]), *args, **kwargs)

    def post(self, url, *args, **kwargs):
        if url.startswith("/"):
            url = url[1:]

        if self.method == "secretkey":
            if "data" not in kwargs:
                kwargs["data"] = {}

            kwargs["data"][self.secretname] = self.key
        else:
            logger.debug(f"POST {'/'.join([self.host, self.render, url])} {kwargs}")

        return super().post("/".join([self.host, self.render, url]), *args, **kwargs)

    def login(self):
        if self.method == "secretkey":
            logger.debug(f"{self.method=} requires no login")
        else:
            if self.method in ("userpassword", "userpassword+otp"):
                answ = self.post("/user/auth_userpassword/login",
                                 data={"name": self.user,
                                       "password": self.password,
                                       "skey": self.skey()},
                                 timeout=30)
            elif self.method == "loginkey":
                answ = self.post("/user/auth_loginkey/login",
                                 data={"key": self.key,
                                       "skey": self.skey()},
                                 timeout=30)

            while True:
                if answ.status_code == 200:
                    try:
                        res = answ.json()
                    except (json.decoder.JSONDecodeError, requests.exceptions.JSONDecodeError):
                        try:
                            res = json.loads(re.search(r"JSON\(\((.*)\)\)", answ.text).group(1))
                        except Exception:
                            res = None

                    if res:
                        if res == "OKAY":
                            break
                        elif self.method == "userpassword+otp" and res["action"] == "otp":
                            answ = self.post("/user/f2_timebasedotp/otp",
                                             data={"otptoken": self.otp,
                                                   "skey": self.skey()},
                                             timeout=30)
                            continue

                logger.error(f"Unable to logon to {self.host!r}, got {answ=} with {answ.text=}")
                return False

        logger.debug(f"HELLO {self.host}")
        return True

    def list(self, module, *args, **kwargs):
        req = self.get(f"/{module}/list", params=kwargs, timeout=60)

        if not req.status_code == 200:
            logger.error(f"Error {req.status_code!r}, unable to fetch items")
            return None

        return req.json()

    def flatlist(self, module, *args, **kwargs):
        req = self.get(f"/{module}/listentries", params=kwargs, timeout=60)

        if not req.status_code == 200:
            logger.error(f"Error {req.status_code!r}, unable to fetch items")
            return None

        return req.json()

    def flatten_relational_data(self, bone_name, data):
        ret = {}
        if isinstance(data, list) or isinstance(data, dict):
            if isinstance(data, dict):
                data = [data]
            for i, entry in enumerate(data):
                prefix = bone_name + ".%d." % i
                ret[prefix + "key"] = entry["dest"]["key"]
                if entry["dest"]["rel"]:
                    for key, value in entry["dest"]["rel"].items():
                        ret[prefix + key] = value
        else:
            ret[bone_name] = data
        return ret

    def view(self, module, key):
        req = self.get(f"/{module}/view/{key}", timeout=10)

        if not req.status_code == 200:
            logger.error(f"Error {req.status_code!r}, unable to fetch entry")
            return None

        return req.json()

    def import_file(self, info):
        assert "dlkey" in info and "name" in info

        name = info["name"]
        dlkey = info["dlkey"]
        servingurl = info.get("servingurl")
        size = info["size"]

        if not isinstance(size, int):
            try:
                size = int(size)
            except ValueError:
                logger.error("cannot convert {size!r} to int", size)
                return None

        if size > 200_000_000:
            logger.error("Download skipped, because its larger than 200mb")
            logger.error(info)
            return None

        if not (mimetype := info.get("mimetype")):
            mimetype = mimetypes.guess_type(name)[0]

        if "downloadUrl" in info:
            # ViUR 3
            logger.debug(f"Downloading {self.host + info['downloadUrl']}")
            res = self.get(info["downloadUrl"], timeout=60)
        else:
            # ViUR 2
            logger.debug(f"Downloading {self.host + '/file/download/' + dlkey}")
            res = self.get("/file/download/" + dlkey, timeout=60)
        if not res.ok:
            if servingurl:
                logger.warning(f"Download failed, trying to fetch using {servingurl=}")
                content = super().get(servingurl).content
            else:
                logger.error(f"Download failed with {res.status_code=}")
                return None
        else:
            content = res.content

        logger.debug(f"{name=} has {len(content)!r} bytes")

        return conf.main_app.file.write(name, content, mimetype)

    def set_skel_value(self, skel: SkeletonInstance, bone_name: str, value: t.Any, debug: bool = False):
        changes = 0
        bone = getattr(skel, bone_name)

        if bone is None:
            return changes

        bone_value = skel[bone_name]
        if isinstance(bone, bones.FileBone):
            knownFiles = {}

            if debug:
                logger.debug(f"{bone_value=}")

            if bone_value:
                if bone.languages and isinstance(value, dict):
                    if bone_value is None:
                        bone_value = {}

                    for lang, val in value.items():
                        if lang in bone.languages:
                            if not bone_value.get(lang):
                                continue

                            if isinstance(bone_value[lang], dict):
                                knownFiles[bone_value[lang]["dest"]["name"]] = bone_value[lang]
                            else:
                                for entry in bone_value[lang]:
                                    knownFiles[entry["dest"]["name"]] = entry


                elif isinstance(skel[bone_name], dict):
                    knownFiles[skel[bone_name]["dest"]["name"]] = skel[bone_name]
                else:
                    for entry in skel[bone_name]:
                        knownFiles[entry["dest"]["name"]] = entry

            # knownFiles.clear() #Temporary enabled to clear all files

            if debug:
                logger.debug(f"{bone_name} knownFiles = {knownFiles!r}")

            def handle_entries(changes, value, lang=None):
                for entry in value:
                    # fixme: not sure why, but while importing fluidpagecontent files, some entries where None... skipping
                    if not entry:
                        continue

                    if debug:
                        logger.debug(f"{entry=} // {lang=}")

                    fileName = entry["dest"]["name"]
                    key = None

                    if fileName not in knownFiles:
                        if debug:
                            logger.debug(f"{bone_name} name {fileName=} is not known")

                        key = self.import_file(entry["dest"])
                        if not key:
                            continue
                        # assert (key := self.import_file(entry["dest"]))

                    if not bone.using:
                        if key:
                            if skel.setBoneValue(bone_name, key, append=bone.multiple, language=lang):
                                changes += 1
                            else:
                                logger.error(f"Unable to set bone {bone_name} to {key}")

                    else:
                        assert entry["rel"]
                        using_skel = bone.using()
                        using_skel.unserialize(knownFiles[fileName]["rel"] if fileName in knownFiles else {})
                        changes += self.translate(using_skel, entry["rel"])

                        if key:
                            if skel.setBoneValue(bone_name, (key, using_skel), append=bone.multiple, language=lang):
                                changes += 1
                            else:
                                logger.error(f"Unable to set bone {bone_name} to {key}")
                        else:
                            knownFiles[fileName]["rel"].unserialize(using_skel.dbEntity)
                return changes

            if bone.languages and isinstance(value, dict):
                for lang, val in value.items():
                    if lang in bone.languages:
                        if not bone_value.get(lang):
                            continue

                        if isinstance(val, dict):
                            val = [val]
                        changes = handle_entries(changes, val, lang)

            else:

                if isinstance(value, dict):
                    value = [value]

                changes = handle_entries(changes, value)

        elif isinstance(bone, bones.RelationalBone):

            if isinstance(value, (dict, str, type(db.Key))):
                value = [value]
            elif value is None:
                value = []

            if bone_value and isinstance(bone_value, (dict, str, type(db.Key))):
                bone_value = [bone_value]
            elif not bone_value:
                bone_value = []

            skel[bone_name] = None

            # A difference in length is always a diff indicator!
            if len(value) != len(bone_value):
                changes += 1

            # Deep iterate through bone values
            for nentry in value:
                if bone_value:
                    # There is an old entry
                    oentry = bone_value.pop(0)

                else:
                    # Old entry does not exist
                    oentry = None

                if bone.using:
                    using_skel = bone.using()
                else:
                    using_skel = None

                # Rewrite the key of the referenced entity
                if isinstance(nentry, dict):
                    assert "rel" in nentry and "dest" in nentry, "This doesn't look like a RelationalBone"
                    key = db.Key(bone.kind, db.KeyClass.from_legacy_urlsafe(nentry["dest"]["key"]).id_or_name)

                elif isinstance(nentry, (str, db.Key)):
                    key = nentry
                else:
                    raise ValueError()

                # In case of an using_skel, check for differences also.
                if using_skel:
                    using_skel.unserialize(oentry["rel"] if oentry else {})
                    changes += self.translate(
                        using_skel, nentry["rel"] or {},
                        {k: k for k in using_skel.keys()},
                        debug=debug
                    )

                    if not skel.setBoneValue(bone_name, (key, using_skel), append=bone.multiple):
                        logger.error(f"Unable to set bone {bone_name} to {key}")

                elif not skel.setBoneValue(bone_name, key, append=bone.multiple):
                    logger.error(f"Unable to set bone {bone_name} to {key}")

        elif isinstance(bone, bones.RecordBone):
            def set_value(val, lang):
                nonlocal bone_value, changes, key

                if isinstance(val, (dict, str, db.Key)):
                    val = [val]
                elif val is None:
                    val = []

                if bone_value and isinstance(bone_value, (dict, str, db.Key)):
                    bone_value = [bone_value]
                elif not bone_value:
                    bone_value = []

                if bone.languages:
                    skel[bone_name] = {lang: [] if bone.multiple else None
                                      for lang in bone.languages}
                else:
                    skel[bone_name] = [] if bone.multiple else None

                for nentry in val:
                    if bone_value:
                        # There is an old entry
                        oentry = bone_value.pop(0)

                    else:
                        # Old entry does not exist
                        oentry = None
                        changes += 1

                    using_skel = bone.using()
                    using_skel.unserialize(oentry or {})

                    changes += self.translate(using_skel, nentry, {k: k for k in using_skel.keys()}, debug=debug)

                    if debug:
                        logger.debug(f"Assign {bone_name=}, {using_skel=}, append={bone.multiple}, language={lang}")
                    if not skel.setBoneValue(bone_name, using_skel, append=bone.multiple, language=lang):
                        logger.error(f"Unable to set bone {bone_name}.{lang} to {using_skel}")

            if debug:
                logger.debug(f"{bone.languages=} // {value}")

            if bone.languages:
                for lang in bone.languages:
                    if value.get(lang):
                        set_value(value[lang], lang)
            else:
                set_value(value, None)


        elif bone.languages and isinstance(value, dict):
            if bone_value is None:
                bone_value = {}

            if debug:
                logger.debug(f"{bone_value=} {value=} {bone=}")

            for lang, val in value.items():
                if lang in bone.languages:
                    if lang not in bone_value:
                        changes += 1
                    elif bone_value[lang] != val:
                        changes += 1

                    if bone.multiple:
                        if val is None:
                            val = []
                        elif isinstance(val, (str, numbers.Number)):
                            val = [val]
                        elif not isinstance(val, list):
                            logger.warning(f"Unexpected {val=}")

                    bone_value[lang] = val

            skel[bone_name] = bone_value

        elif isinstance(bone, bones.DateBone):
            skel.setBoneValue(bone_name, value)

            if bone_value != skel[bone_name]:
                changes += 1

        else:
            if bone.multiple:
                if not isinstance(value, list):
                    value = [value]
            else:
                if isinstance(value, list) and len(value) == 1:
                    value = value[0]

            new_value_as_str = html.unescape(str(bone_value)).strip()
            old_value_as_str = html.unescape(str(value)).strip()

            if debug:
                logger.debug(
                    f"{bone_name} old={old_value_as_str!r} != new:{new_value_as_str!r}? "
                    f"{new_value_as_str != old_value_as_str!r}"
                )

            if new_value_as_str != old_value_as_str:
                if bone.multiple and not isinstance(value, list):
                    value = [value]

                skel[bone_name] = value
                changes += 1

                if debug:
                    logger.debug(f"{bone_name} new value {skel[bone_name]=}")

                '''
                # Turn value into a list to avoid implementing below code twice
                if not isinstance(value, list):
                    value = [value]

                skel[bone_name] = None

                for val in value:
                    if skel.setBoneValue(bone_name, str(val), append=bone.multiple):
                        changes += 1
                    else:
                        logger.error("Unable to set bone %r to %r", bone_name, val)

                if debug:
                    logger.debug("%s new value %r", bone_name, skel[bone_name])
                '''

        # if changes:
        #	logger.debug("%r has %d changes", bone_name, changes)

        return changes

    def translate(self, skel: SkeletonInstance, values, translate=None, debug: bool = False):
        changes = 0

        if translate is None:
            translate = {k: k for k in skel.keys()}

        for bone, tr in translate.items():
            if debug:
                logger.debug(f"{bone=}, {tr=}, {values.get(bone)=}")

            if bone.endswith("*"):
                for k, v in values.items():
                    if k.startswith(bone[:-1]):
                        tail = k[len(bone[:-1]):]

                        if isinstance(tr, str):
                            if tr:
                                if tr.endswith("*"):
                                    lookfor = tr[:-1] + tail
                                else:
                                    lookfor = tr + tail
                            else:
                                lookfor = k

                            if lookfor in skel:
                                old = skel[lookfor]

                                # Set to empty (don't do this with set_skel_value)
                                if not v:
                                    if skel[lookfor]:
                                        if debug:
                                            logger.debug(f"{lookfor!r} changed from {old!r} to {v!r}")

                                        changes += 1

                                    skel[lookfor] = getattr(skel, lookfor).getDefaultValue(skel)

                                elif ch := self.set_skel_value(skel, lookfor, v, debug=debug):
                                    if debug:
                                        logger.debug(f"{lookfor!r} changed from {old!r} to {skel[lookfor]!r}")

                                    changes += ch

                        elif callable(tr):
                            changes += tr(
                                skel=skel,
                                bone=bone,
                                value=values[k],
                                values=values,
                                module=self
                                # TODO: k is missing (key from incoming values)
                            )

            elif bone in values:

                if tr and isinstance(tr, str):
                    if tr in skel:
                        old = skel[tr]

                        # Set to empty (don't do this with set_skel_value)
                        if not values[bone]:
                            if skel[tr]:
                                if debug:
                                    logger.debug(f"{tr!r} changed from {old!r} to {values[bone]!r}")

                                changes += 1
                            bone_instance = getattr(skel, tr)
                            if bone_instance.multiple:
                                skel[tr] = []
                            else:
                                skel[tr] = bone_instance.getDefaultValue(skel)
                        else:
                            if debug:
                                logger.debug(f"setting {tr!r} to {values[bone]!r}")

                            try:
                                if ch := self.set_skel_value(skel, tr, values[bone], debug=debug):
                                    if debug:
                                        logger.debug(f"{tr!r} changed from {old!r} to {skel[tr]!r}")

                                    changes += ch

                            except:  # db.Error:
                                raise
                                logger.warning(f"Unable to set value for {tr=!r}")

                elif callable(tr):
                    changes += tr(
                        skel=skel,
                        bone=bone,
                        value=values[bone],
                        values=values,
                        module=self
                    )

            elif debug:
                logger.debug(f"Skipping {bone=}")

        return changes

    def values_to_skel(
        self,
        skel: SkeletonInstance,
        values: dict,
        translate: dict = {},
        reset: t.Optional[str | t.Iterable[str]] = None,
        source_key: str = "key",
        update: bool = True,
        enforce: bool = False,
        debug: bool = False
    ):
        # assert isinstance(skel, skeleton.BaseSkeleton), "'skel' must be a BaseSkeleton instance"
        assert source_key in values, f"'{source_key}' not in values"

        changes = 0
        exists = True

        try:
            key = db.KeyClass.from_legacy_urlsafe(values[source_key])
        except AttributeError:
            key = db.keyHelper(values[source_key], skel.kindName)

        key = db.Key(skel.kindName, key.id_or_name)

        success = skel.fromDB(key)

        if "import_behavior" in skel and skel["import_behavior"] in ("preserve", "keep"):
            return changes  # dont change skels with this behaviors

        if not enforce and success:
            if not update:
                logger.debug(f"{skel.kindName} entity with {key=} exists, but no update wanted")
                return changes
        else:
            if enforce:
                logger.debug(f"Creation of {skel.kindName} entity with {key=} will be enforced.")
            else:
                logger.debug(f"{skel.kindName} entity with {key=} does not not exist")
                exists = False

            skel["key"] = key
            changes += 1

        if reset:
            if isinstance(reset, list):
                for bone in reset:
                    skel[bone] = None

            else:
                assert isinstance(reset, str)
                skel[reset] = None

        changes += self.translate(skel, values, translate, debug=debug)

        if changes:
            logger.debug(f"{skel.kindName} {key=} detected {changes=}")

        if debug:
            logger.debug("--- values_to_skel ---")

            for bone in skel.keys():
                logger.debug(
                    f"{bone=} (multiple={getattr(skel, bone).multiple}, languages={getattr(skel, bone).languages}) => {skel[bone]!r}",
                )

        return changes if exists else -1


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
    }
    _bone_translation_table = None  # the final translation table once created by create_config()

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
            logging.exception("Can't convert key")
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
        inform: str = None,
        dry_run: bool = False,
        otp=None,
        debug: bool = False,
        **kwargs,
    ):
        cuser = current.user.get()
        if not cuser or "root" not in cuser["access"]:
            raise errors.Unauthorized()

        # Additional credentials
        import_conf = self.import_conf() if callable(self.import_conf) else self.import_conf

        source = import_conf.get("source") or {}

        if source.get("type") == "viur" and source.get("auth") == "userpassword+otp":
            # Hint for OTP
            if not otp:
                raise errors.BadRequest("Requires 'otp' key to succeed")

            source["otp"] = otp

        if self.get_handler() == "tree":
            kwargs.setdefault("skelType", "node")
            kwargs.setdefault("_autoSkelType", True)

        if not inform:
            inform = import_conf.get("inform", False)
            inform = inform if isinstance(inform, str) else cuser["name"] if inform else None

        self.do_import(
            inform=inform,
            follow=follow,
            enforce=enforce,
            dry_run=dry_run,
            source=source or None,
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
        dry_run=False,
        cookies=None,
        source=None,
        delete_filter=None,
        debug: bool = False,
        **kwargs,
    ):
        import_conf = self.import_conf() if callable(self.import_conf) else self.import_conf
        assert import_conf.get("source"), "No source specified to import from"

        # Mark this request as an import task
        current.request.get().kwargs["isImportTask"] = True  # FIXME!
        if importdate is None:
            importdate = utils.utcNow().replace(microsecond=0)  # need to remove microseconds!!!

        logging.debug(f"{self.moduleName!r} {importdate=} {total=}")

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
            logging.error(f"Cannot fetch list from {url=}, {answ.status_code=}")
            raise errors.BadRequest()

        try:
            answ = answ.json()

        except:
            logging.warning(
                "Target module %r does not exist in source or some other error occured - skipping",
                import_conf.get("module", self.moduleName),
            )
            self._kickoff_follow(importdate, inform, **kwargs)
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

            # logging.debug(f"{values=}")

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
                        "sourceportal": import_conf.get("url"),
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
        import_conf = self.import_conf() if callable(self.import_conf) else self.import_conf

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
        self._bone_translation_table = tr

    def do_import_entry(
        self, key, import_conf=None, module=None, kindName=None, skel_type="node",
        debug: bool = False,
    ):
        if not import_conf:
            import_conf = self.import_conf() if callable(self.import_conf) else self.import_conf

        importdate = utils.utcNow()

        # Login
        try:
            imp = Importer(
                import_conf.get("url"), import_conf.get("source") or {},
                render=import_conf.get("render", "vi")
            )

        except Exception as e:
            logging.exception(e)
            return

        skel = self.import_skel(skelType=skel_type)

        self.create_config(skel)

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
            logging.error(
                "Cannot fetch list from %r, error %d occured", url, answ.status_code
            )
            raise errors.BadRequest()

        try:
            answ = answ.json()
        except:
            logging.warning(
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

        import_conf = self.import_conf() if callable(self.import_conf) else self.import_conf

        for name in import_conf.get("follow") or []:
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
        import_conf=None,
        cursor=None,
        removed=0,
        follow=False,
        dry_run=False,
        delete_filter=None,
        **kwargs,
    ):
        logging.info("do_clear")
        _importConfName = import_conf
        if import_conf:
            _importConf = getattr(self, import_conf)
            import_conf = _importConf() if callable(_importConf) else _importConf
        else:
            import_conf = (
                self.import_conf() if callable(self.import_conf) else self.import_conf
            )

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
                import_conf=_importConfName,
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
                    "sourceportal": import_conf.get("url"),
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
