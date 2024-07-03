"""
Importer module.

This module is a library used by the Importable prototype.
"""
import html
import json
import logging
import mimetypes
import numbers
import re
import requests
import typing as t
from viur.core import bones, conf, db
from viur.core.skeleton import SkeletonInstance

logger = logging.getLogger(__name__)


class Importer(requests.Session):
    def __init__(self, portal, render="vi", creds=None, cookies=None):
        super(Importer, self).__init__()
        from .abstracts.importable import Importable

        if not (Importable.get_interface_config() and Importable.get_interface_config().get("import")):
            raise IOError("No import interfaces defined in configuration")

        cfg = Importable.get_interface_config()["import"].get(portal)
        if cfg is None:
            raise IOError("Importer %r is disabled by configuration" % portal)

        assert "type" in cfg, "Configuration for '%r' is incomplete" % portal
        if cfg["type"] == "viur":
            assert all([x in cfg for x in ["auth", "host"]]), "Configuration for '%r' is incomplete" % portal

        self.render = render
        self.portal = portal
        self.method = cfg.get("auth")
        self.host = cfg.get("host", "http://localhost")
        self.secretname = self.user = self.password = self.key = self.otp = None

        if cookies:
            logger.info(f"Using existing session cookies {cookies.keys()}")
            self.cookies.update(cookies)
            return

        if creds:
            # allow to extend configuration credentials by caller (e.g. to extend credentials asked for)
            cfg |= {k: v for k, v in creds.items() if k in ("user", "pass", "secretkey", "otp")}

        if self.method == "userpassword":
            self.user = cfg["user"]
            self.password = cfg["pass"]
        elif self.method == "userpassword+otp":
            self.user = cfg["user"]
            self.password = cfg["pass"]
            self.otp = cfg["otp"]
        elif self.method in ["secretkey", "loginkey"]:
            self.secretname = cfg.get("keyname", "secret")

            if module := cfg.get("from"):
                if "." in module:
                    module, key = module.split(".", 1)
                else:
                    key = portal
                mod = getattr(conf.main_app.vi, module)  # fixme: viur-core 3.7 Remove vi when possibel!
                mod = db.Get(db.Key(mod.viewSkel().kindName, mod.getKey()))
                self.key = mod[key]
            else:
                self.key = cfg.get("key")

            assert self.key, "No key defined?"
        elif self.method is not None:
            raise ValueError("Unsupported authmethod configuration %r" % self.method)

        if self.method and not self.login():
            raise IOError("Unable to logon to '%s'" % self.host)

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
            logger.debug("GET  %s %s" % ("/".join([self.host, self.render, url]), kwargs))

        return super(Importer, self).get("/".join([self.host, self.render, url]), *args, **kwargs)

    def post(self, url, *args, **kwargs):
        if url.startswith("/"):
            url = url[1:]

        if self.method == "secretkey":
            if "data" not in kwargs:
                kwargs["data"] = {}

            kwargs["data"][self.secretname] = self.key
        else:
            logger.debug("POST %s %s" % ("/".join([self.host, self.render, url]), kwargs))

        return super(Importer, self).post("/".join([self.host, self.render, url]), *args, **kwargs)

    def login(self):
        if self.method == "secretkey":
            logger.debug("%r requires no login", self.method)
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

        logger.debug(f"HELLO {self.portal} at {self.host}")
        return True

    def list(self, module, *args, **kwargs):
        req = self.get("/%s/list" % module, params=kwargs, timeout=60)

        if not req.status_code == 200:
            logger.error("Error %d, unable to fetch items" % req.status_code)
            return None

        return req.json()

    def flatlist(self, module, *args, **kwargs):
        req = self.get("/%s/listentries" % module, params=kwargs, timeout=60)

        if not req.status_code == 200:
            logger.error("Error %d, unable to fetch items" % req.status_code)
            return None

        return req.json()

    def flattenRelationalData(self, boneName, data):
        ret = {}
        if isinstance(data, list) or isinstance(data, dict):
            if isinstance(data, dict):
                data = [data]
            for i, entry in enumerate(data):
                prefix = boneName + ".%d." % i
                ret[prefix + "key"] = entry["dest"]["key"]
                if entry["dest"]["rel"]:
                    for key, value in entry["dest"]["rel"].items():
                        ret[prefix + key] = value
        else:
            ret[boneName] = data
        return ret

    def view(self, module, key):
        req = self.get("/%s/view/%s" % (module, key), timeout=10)

        if not req.status_code == 200:
            logger.error("Error %d, unable to fetch entry" % req.status_code)
            return None

        return req.json()

    def importFile(self, info):
        assert "dlkey" in info and "name" in info

        name = info["name"]
        dlkey = info["dlkey"]
        servingurl = info.get("servingurl")
        size = info["size"]
        if not isinstance(size, int):
            try:
                size = int(size)
            except:
                logger.error("cannot convert %r to int", size)
                return None
        if size > 200000000:
            logger.error("Download skipped, because its larger than 200mb")
            logger.error(info)
            return None

        if not (mimetype := info.get("mimetype")):
            mimetype = mimetypes.guess_type(name)[0]

        if "downloadUrl" in info:
            # ViUR 3
            logger.debug("Downloading %s" % (self.host + info["downloadUrl"]))
            res = self.get(info["downloadUrl"], timeout=60)
        else:
            # ViUR 2
            logger.debug("Downloading %s" % (self.host + "/file/download/" + dlkey))
            res = self.get("/file/download/" + dlkey, timeout=60)
        if not res.ok:
            if servingurl:
                logger.warning("Download failed, trying to fetch using servingurl %r", servingurl)
                content = super(Importer, self).get(servingurl).content
            else:
                logger.error("Download failed, %r", res.status_code)
                return None
        else:
            content = res.content

        logger.debug("%r has %d bytes", name, len(content))

        key = conf.main_app.file.write(name, content, mimetype)

        '''
        if key:
            # Ganz toll gelöst, damit es auch mit Umlauten klappt... Danke, Google.
            fskel = fileBaseSkel()
            fskel.fromDB(key)
            fskel["name"] = name

            return fskel.toDB(clearUpdateTag=True)
        '''

        return key

    def setSkelValue(self, skel: SkeletonInstance, boneName: str, value: t.Any, debug: bool = False):
        changes = 0
        bone = getattr(skel, boneName)

        if bone is None:
            return changes

        boneValue = skel[boneName]
        if isinstance(bone, bones.FileBone):
            knownFiles = {}

            if debug:
                logger.debug(f"{boneValue = }")

            if boneValue:
                if bone.languages and isinstance(value, dict):
                    if boneValue is None:
                        boneValue = {}

                    for lang, val in value.items():
                        if lang in bone.languages:
                            if not boneValue.get(lang):
                                continue

                            if isinstance(boneValue[lang], dict):
                                knownFiles[boneValue[lang]["dest"]["name"]] = boneValue[lang]
                            else:
                                for entry in boneValue[lang]:
                                    knownFiles[entry["dest"]["name"]] = entry


                elif isinstance(skel[boneName], dict):
                    knownFiles[skel[boneName]["dest"]["name"]] = skel[boneName]
                else:
                    for entry in skel[boneName]:
                        knownFiles[entry["dest"]["name"]] = entry

            # knownFiles.clear() #Temporary enabled to clear all files

            if debug:
                logger.debug("%s knownFiles = %r", boneName, knownFiles)

            def handle_entries(changes, value, lang=None):
                for entry in value:
                    # fixme: not sure why, but while importing fluidpagecontent files, some entries where None... skipping
                    if not entry:
                        continue

                    if debug:
                        logger.debug(f"{entry = } // {lang = }")
                    fileName = entry["dest"]["name"]
                    key = None

                    if fileName not in knownFiles:
                        if debug:
                            logger.debug("%s name %s is not known", boneName, fileName)

                        key = self.importFile(entry["dest"])
                        if not key:
                            continue
                        # assert (key := self.importFile(entry["dest"]))

                    if not bone.using:
                        if key:
                            if skel.setBoneValue(boneName, key, append=bone.multiple, language=lang):
                                changes += 1
                            else:
                                logger.error(f"Unable to set bone {boneName} to {key}")

                    else:
                        assert entry["rel"]
                        usingSkel = bone.using()
                        usingSkel.unserialize(knownFiles[fileName]["rel"] if fileName in knownFiles else {})
                        changes += self.translate(usingSkel, entry["rel"])

                        if key:
                            if skel.setBoneValue(boneName, (key, usingSkel), append=bone.multiple, language=lang):
                                changes += 1
                            else:
                                logger.error(f"Unable to set bone {boneName} to {key}")
                        else:
                            knownFiles[fileName]["rel"].unserialize(usingSkel.dbEntity)
                return changes

            if bone.languages and isinstance(value, dict):
                for lang, val in value.items():
                    if lang in bone.languages:
                        if not boneValue.get(lang):
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

            if boneValue and isinstance(boneValue, (dict, str, type(db.Key))):
                boneValue = [boneValue]
            elif not boneValue:
                boneValue = []

            skel[boneName] = None

            # A difference in length is always a diff indicator!
            if len(value) != len(boneValue):
                changes += 1

            # Deep iterate through bone values
            for nentry in value:
                if boneValue:
                    # There is an old entry
                    oentry = boneValue.pop(0)

                else:
                    # Old entry does not exist
                    oentry = None

                if bone.using:
                    usingSkel = bone.using()
                else:
                    usingSkel = None

                # Rewrite the key of the referenced entity
                if isinstance(nentry, dict):
                    assert "rel" in nentry and "dest" in nentry, "This doesn't look like a RelationalBone"

                    if db.KeyClass.from_legacy_urlsafe(nentry["dest"]["key"]).id_or_name in name_fix:
                        key = db.Key(bone.kind,
                                     name_fix[db.KeyClass.from_legacy_urlsafe(nentry["dest"]["key"]).id_or_name])
                    else:
                        key = db.Key(bone.kind, db.KeyClass.from_legacy_urlsafe(nentry["dest"]["key"]).id_or_name)

                elif isinstance(nentry, (str, db.Key)):
                    key = nentry
                else:
                    raise ValueError()

                # In case of an usingSkel, check for differences also.
                if usingSkel:
                    usingSkel.unserialize(oentry["rel"] if oentry else {})
                    changes += self.translate(
                        usingSkel, nentry["rel"] or {},
                        {k: k for k in usingSkel.keys()},
                        debug=debug
                    )

                    if not skel.setBoneValue(boneName, (key, usingSkel), append=bone.multiple):
                        logger.error(f"Unable to set bone {boneName} to {key}")

                elif not skel.setBoneValue(boneName, key, append=bone.multiple):
                    logger.error(f"Unable to set bone {boneName} to {key}")

        elif isinstance(bone, bones.RecordBone):
            def set_value(val, lang):
                nonlocal boneValue, changes, key

                if isinstance(val, (dict, str, db.Key)):
                    val = [val]
                elif val is None:
                    val = []

                if boneValue and isinstance(boneValue, (dict, str, db.Key)):
                    boneValue = [boneValue]
                elif not boneValue:
                    boneValue = []

                if bone.languages:
                    skel[boneName] = {lang: [] if bone.multiple else None
                                      for lang in bone.languages}
                else:
                    skel[boneName] = [] if bone.multiple else None

                for nentry in val:
                    if boneValue:
                        # There is an old entry
                        oentry = boneValue.pop(0)

                    else:
                        # Old entry does not exist
                        oentry = None
                        changes += 1

                    usingSkel = bone.using()
                    usingSkel.unserialize(oentry or {})

                    changes += self.translate(usingSkel, nentry, {k: k for k in usingSkel.keys()}, debug=debug)

                    if debug:
                        logger.debug(f"Assign {boneName=}, {usingSkel=}, append={bone.multiple}, language={lang}")
                    if not skel.setBoneValue(boneName, usingSkel, append=bone.multiple, language=lang):
                        logger.error(f"Unable to set bone {boneName}.{lang} to {usingSkel}")

            if debug:
                logger.debug(f"{bone.languages=} // {value}")

            if bone.languages:
                for lang in bone.languages:
                    if value.get(lang):
                        set_value(value[lang], lang)
            else:
                set_value(value, None)


        elif bone.languages and isinstance(value, dict):
            if boneValue is None:
                boneValue = {}

            if debug:
                logger.debug(f"{boneValue = }")
                logger.debug(f"{value = }")
                logger.debug(f"{bone = }")

            for lang, val in value.items():
                if lang in bone.languages:
                    if lang not in boneValue:
                        changes += 1
                    elif boneValue[lang] != val:
                        changes += 1

                    if bone.multiple:
                        if val is None:
                            val = []
                        elif isinstance(val, (str, numbers.Number)):
                            val = [val]
                        elif not isinstance(val, list):
                            logger.warning(f"Unexpected {val=}")

                    boneValue[lang] = val

            skel[boneName] = boneValue

        elif isinstance(bone, bones.DateBone):
            skel.setBoneValue(boneName, value)

            if boneValue != skel[boneName]:
                changes += 1

        else:
            if bone.multiple:
                if not isinstance(value, list):
                    value = [value]
            else:
                if isinstance(value, list) and len(value) == 1:
                    value = value[0]

            new_value_as_str = html.unescape(str(boneValue)).strip()
            old_value_as_str = html.unescape(str(value)).strip()

            if debug:
                logger.debug(
                    "%s old:%r != new:%r? %r",
                    boneName, new_value_as_str, old_value_as_str,
                    new_value_as_str != old_value_as_str
                )

            if new_value_as_str != old_value_as_str:
                if bone.multiple and not isinstance(value, list):
                    value = [value]

                skel[boneName] = value
                changes += 1

                if debug:
                    logger.debug("%s new value %r", boneName, skel[boneName])

                '''
                # Turn value into a list to avoid implementing below code twice
                if not isinstance(value, list):
                    value = [value]

                skel[boneName] = None

                for val in value:
                    if skel.setBoneValue(boneName, str(val), append=bone.multiple):
                        changes += 1
                    else:
                        logger.error("Unable to set bone %r to %r", boneName, val)

                if debug:
                    logger.debug("%s new value %r", boneName, skel[boneName])
                '''

        # if changes:
        #	logger.debug("%r has %d changes", boneName, changes)

        return changes

    def translate(self, skel: SkeletonInstance, values, translate=None, debug: bool = False):
        changes = 0

        if translate is None:
            translate = {k: k for k in skel.keys()}

        for bone, tr in translate.items():
            if debug:
                logger.debug("bone = %r, tr = %r, val = %r", bone, tr, values.get(bone))

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

                                # Set to empty (don't do this with setSkelValue)
                                if not v:
                                    if skel[lookfor]:
                                        if debug:
                                            logger.debug("%s changed from %r to %r", lookfor, old, v)

                                        changes += 1

                                    skel[lookfor] = getattr(skel, lookfor).getDefaultValue(skel)

                                elif ch := self.setSkelValue(skel, lookfor, v, debug=debug):
                                    if debug:
                                        logger.debug("%s changed from %r to %r", lookfor, old, skel[lookfor])

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

                        # Set to empty (don't do this with setSkelValue)
                        if not values[bone]:
                            if skel[tr]:
                                if debug:
                                    logger.debug("%s changed from %r to %r", tr, old, values[bone])

                                changes += 1
                            bone_instance = getattr(skel, tr)
                            if bone_instance.multiple:
                                skel[tr] = []
                            else:
                                skel[tr] = bone_instance.getDefaultValue(skel)
                        else:
                            if debug:
                                logger.debug("setting %r to %r", tr, values[bone])

                            try:
                                if ch := self.setSkelValue(skel, tr, values[bone], debug=debug):
                                    if debug:
                                        logger.debug("%s changed from %r to %r", tr, old, skel[tr])

                                    changes += ch

                            except:  # db.Error:
                                raise
                                logger.warning("Unable to set value for '%s'", tr)

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

    def toSkel(self, skel: SkeletonInstance, values, translate={}, reset=None, sourceKey="key", update=True,
               enforce=False, debug: bool = False):
        # assert isinstance(skel, skeleton.BaseSkeleton), "'skel' must be a BaseSkeleton instance"
        assert sourceKey in values, "'%s' not in values" % sourceKey

        changes = 0
        exists = True

        try:
            key = db.KeyClass.from_legacy_urlsafe(values[sourceKey])
        except AttributeError:
            key = db.keyHelper(values[sourceKey], skel.kindName)

        key = db.Key(skel.kindName, key.id_or_name)

        success = skel.fromDB(key)

        if "import_behavior" in skel and skel["import_behavior"] in ["preserve", "keep"]:
            return changes  # dont change skels with this behaviors

        if not enforce and success:
            if not update:
                logger.debug("%s entity with key '%s' exists, but no update wanted", skel.kindName, key)
                return changes
        else:
            if enforce:
                logger.debug("Creation of %s entity with key '%s' will be enforced.", skel.kindName, key)
            else:
                logger.debug("%s entity with key '%s' does not not exist", skel.kindName, key)
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
            logger.debug("%s %r detected %d changes", skel.kindName, key, changes)

        if debug:
            logger.debug("--- toSkel ---")

            for bone in skel.keys():
                logger.debug(
                    "%r (multiple=%r, languages=%r) => %r",
                    bone, getattr(skel, bone).multiple, getattr(skel, bone).languages, skel[bone]
                )

        return changes if exists else -1
