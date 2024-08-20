"""
`Importer` is a `requests.Session`-inherited class which provides helpers to convert
from JSON into a skeleton structure.
"""

import html
import json
import logging
import mimetypes
import numbers
import re
import typing as t

import requests
from requests import Response

from viur.core import bones, conf, db, skeleton, utils

if t.TYPE_CHECKING:
    from .importable import Importable

NIL: t.Final = object()

logger = logging.getLogger(__name__)


class Importer(requests.Session):

    def __init__(self, source: dict, render: str = "vi", cookies: dict | None = None):
        from .. import get_task_retry_count

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

            if get_task_retry_count() > 1 and self.get("/user/view/self").status_code == 401:
                logger.warning("Got 401, session seems to be expired, Re-Login")
                self.cookies.clear()
            else:
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

                mod = getattr(conf.main_app.vi, module)  # fixme: viur-core 3.7 Remove vi when possible!
                mod = db.Get(db.Key(mod.viewSkel().kindName, mod.getKey()))
                self.key = mod[key]
            else:
                self.key = source.get("key")

            assert self.key, "No key defined?"

        elif self.method is not None:
            raise ValueError(f"Unsupported authmethod configuration {self.method!r}")

        if self.method and not self.login():
            raise IOError(f"Unable to logon to '{self.host}'")

    def logout(self) -> t.Any:
        if self.method != "secretkey":
            return self.get("/user/logout", params={"skey": self.skey()}, timeout=30).json()

    def skey(self) -> str:
        return self.get("/skey", timeout=30).json()

    def get(self, url: str, *args: t.Any, **kwargs: t.Any) -> Response:  # type: ignore[override]
        if url.startswith("/"):
            url = url[1:]

        if self.method == "secretkey":
            if "data" not in kwargs:
                kwargs["data"] = {}

            kwargs["data"][self.secretname] = self.key
        else:
            logger.debug(f"GET  {'/'.join([self.host, self.render, url])} {kwargs}")

        return super().get("/".join([self.host, self.render, url]), *args, **kwargs)

    def post(self, url: str, *args: t.Any, **kwargs: t.Any) -> Response:  # type: ignore[override]
        if url.startswith("/"):
            url = url[1:]

        if self.method == "secretkey":
            if "data" not in kwargs:
                kwargs["data"] = {}

            kwargs["data"][self.secretname] = self.key
        else:
            logger.debug(f"POST {'/'.join([self.host, self.render, url])} {kwargs}")

        return super().post("/".join([self.host, self.render, url]), *args, **kwargs)

    def login(self) -> bool:
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
                            res = json.loads(
                                re.search(r"JSON\(\((.*)\)\)", answ.text).group(1))  # type:ignore[union-attr]
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

    def list(self, module: str, **kwargs: t.Any) -> dict[str, t.Any] | None:
        req = self.get(f"/{module}/list", params=kwargs, timeout=60)

        if not req.status_code == 200:
            logger.error(f"Error {req.status_code!r}, unable to fetch items")
            return None

        return req.json()

    def flatlist(self, module: str, **kwargs: t.Any) -> dict[str, t.Any] | None:
        req = self.get(f"/{module}/listentries", params=kwargs, timeout=60)

        if not req.status_code == 200:
            logger.error(f"Error {req.status_code!r}, unable to fetch items")
            return None

        return req.json()

    def flatten_relational_data(self, bone_name: str, data: t.Any) -> dict[str, t.Any]:
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

    def view(self, module: str, key: str) -> dict[str, t.Any] | None:
        req = self.get(f"/{module}/view/{key}", timeout=10)

        if not req.status_code == 200:
            logger.error(f"Error {req.status_code!r}, unable to fetch entry")
            return None

        return req.json()

    def import_file(self, info: dict[str, t.Any]) -> None | db.Key:
        assert "dlkey" in info and "name" in info

        name = info["name"]
        dlkey = info["dlkey"]
        servingurl = info.get("servingurl")
        try:
            size = info["size"]
        except KeyError:
            logger.warning(f"size is missing in {info=}")
            size = -1

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

        file_skel_cls = skeleton.skeletonByKind("file")
        if "import_key" in dir(file_skel_cls):
            logger.debug(f'[importFile] Looking for {info["key"]}')

            if file_skel := file_skel_cls().all().filter("import_key =", info["key"]).getSkel():
                logger.debug(f"[importFile] File {info} already imported as {file_skel}")
                return file_skel["key"]

            logger.debug(f"[importFile] File {info} not imported yet")

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

        if "import_key" in dir(file_skel_cls):
            return conf.main_app.vi.file.write(name, content, mimetype, import_key=info["key"])

        return conf.main_app.file.write(name, content, mimetype)

    def set_skel_value(self, skel: skeleton.SkeletonInstance, bone_name: str, value: t.Any, debug: bool = False) -> int:
        # FIXME: This method is a total mess up of bone types and nested structure.
        #        It needs a complete refactoring (split into methods), should use more bone methods
        #        and a more robust behaviour against invalid bone data

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

            def handle_entries(changes: int, value: t.Any, lang: str | None = None) -> int:
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
            def set_value(val: t.Any, lang: str | None) -> None:
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

                    logger.debug(f"{val=} IN")

                    if isinstance(bone, bones.BooleanBone):
                        val = [utils.parse.bool(value) for value in val]

                    elif isinstance(bone, bones.NumericBone):
                        values = []
                        for value in val:
                            try:
                                value = float(value)

                            except ValueError:
                                logger.error(f"Not a numeric value for {bone_name}: {value=}")
                                value = bone.getDefaultValue()

                            values.append(value)

                        val = values

                    logger.debug(f"{val=} OUT")

                    try:
                        if not skel.setBoneValue(bone_name, val, language=lang):
                            logger.error(f"Failed to set {bone_name=} {lang=} to {value=}")

                    except Exception as exc:  # noqa
                        exc.add_note(f"{bone_name=} | {bone_value=} | {lang=} | {val=}")
                        raise

        elif isinstance(bone, bones.DateBone):
            skel.setBoneValue(bone_name, value)

            if bone_value != skel[bone_name]:
                changes += 1

        else:  # TODO: this is duplicate code (it's just the inner part of the language for loop)
            if bone.multiple:
                if not isinstance(value, list):
                    value = [value]
            else:
                if isinstance(value, list) and len(value) == 1:
                    value = value[0]

            if isinstance(bone, bones.BooleanBone):
                logger.debug(f"{value=} [IN]")

                if bone.multiple:
                    value = [utils.parse.bool(v) for v in value]
                else:
                    value = utils.parse.bool(value)

                logger.debug(f"{value=} [OUT]")

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

                if not skel.setBoneValue(bone_name, value):
                    logger.error(f"Failed to set {bone_name=} to {value=}")

                changes += 1

                if debug:
                    logger.debug(f"{bone_name} new value {skel[bone_name]=}")

        return changes

    def translate(
        self,
        skel: skeleton.SkeletonInstance,
        values: dict[str, t.Any],
        translate: dict[str, str | t.Callable] | None = None,
        debug: bool = False,
    ) -> int:
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

            elif bone in skel and callable(tr):
                changes += tr(
                    skel=skel,
                    bone=bone,
                    value=NIL,
                    values=values,
                    module=self
                )

            elif debug:
                logger.debug(f"Skipping {bone=}")

        return changes

    def values_to_skel(
        self,
        skel: skeleton.SkeletonInstance,
        values: dict,
        translate: dict = {},
        reset: t.Optional[str | t.Iterable[str]] = None,
        source_key: str = "key",
        update: bool = True,
        enforce: bool = False,
        debug: bool = False,
        module: t.Optional["Importable"] = None,
    ) -> int:
        # assert isinstance(skel, skeleton.BaseSkeleton), "'skel' must be a BaseSkeleton instance"
        assert source_key in values, f"'{source_key}' not in values"

        changes = 0
        exists = True

        try:
            key = db.KeyClass.from_legacy_urlsafe(values[source_key])
        except AttributeError:
            key = db.keyHelper(values[source_key], skel.kindName)

        key = db.Key(skel.kindName, key.id_or_name)

        if module is not None:
            key = module.modify_skel_key(key, skel, values, translate, source_key)

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
