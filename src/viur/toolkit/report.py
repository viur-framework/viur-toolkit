import collections
import csv
import datetime
import json
import logging

import gcsutils
from viur.core import utils

# TODO: re-implement with ViUR3

__all__ = ["Report"]

logger = logging.getLogger(__name__)


class UnicodeDictWriter(csv.DictWriter):
    def writerow(self, rowdict):
        return csv.DictWriter.writerow(
            self, self._ensure_ascii(rowdict)
        )

    def writerows(self, rowdicts):
        return csv.DictWriter.writerows(
            self, list(map(self._ensure_ascii, rowdicts))
        )

    def _ensure_ascii(self, rowdict):
        for k, v in list(rowdict.items()):
            if isinstance(v, str):
                rowdict[k] = v.encode("utf-8")
        return rowdict


class Report(object):
    __slots__ = ("name", "content", "columns", "changed")

    def __init__(self, name):
        self.name = name
        self.content = []
        self.columns = set()
        self.changed = False

    @property
    def gscName(self):
        return "reports/report_{0}.json".format(self.name)

    def _read(self, raiseExc=False):
        try:
            content = json.loads(gcsutils.read(self.gscName))  # type: list
        except AttributeError as exc:  # doesn't exist
            # logger.exception(exc)
            if raiseExc:
                raise exc
            else:
                return None
        columns = content.pop(0)
        self.content = content
        self.columns = set(columns)

    def write(self, **value):
        value["reportdate"] = datetime.datetime.now().isoformat(" ").split(".")[0]
        self.content.append(value)
        self.columns.update(list(value.keys()))
        self.changed = True

    def flush(self):
        if not self.changed:
            return
        value = self.content[:]
        value.insert(0, list(self.columns))
        gcsutils.write(self.gscName, json.dumps(value), "application/json")
        self.changed = False

    def read(self):
        self._read()
        return self.content

    def delete(self):
        # mark as not changed, so it won't be flushed
        self.changed = False
        try:
            gcsutils.delete(self.gscName)
        except AttributeError:  # already deleted
            logger.debug(self.gscName, exc_info=True)

    def sendAsMail(self, receiver):
        header = list(self.columns)
        body = [
            collections.OrderedDict((key, entry.get(key)) for key in header)
            for entry in self.content
        ]

        io = io.StringIO()
        if self.content:
            writer = UnicodeDictWriter(io, fieldnames=header)
            writer.writerows(self.content)
        else:
            io.write("- no entries -")
        io.seek(0)

        # noinspection PyTypeChecker
        return email.sendEMail(
            dests=receiver,
            # language=Jinja2
            name="""Report {{ skel["name"] }}
<table>
	<thead>
		<tr>
			{% for col in skel["header"] %}
				<th>{{ col }}</th>
			{% endfor %}
		</tr>
	</thead>
	<tbody>
		{% if not skel["body"] %}
			<tr>- no entries -</td></tr>
		{% endif %}
		{% for row in skel["body"] %}
			{%- set style = "" -%}
			{%- set level = (row["level"] or "").lower() -%}
			{%- if level == "info" -%}
				{%- set style = "color:dodgerblue" -%}
			{%- elif level == "warning" -%}
				{%- set style = "color:orange" -%}
			{%- elif level == "error" -%}
				{%- set style = "color:red" -%}
			{%- endif -%}
			<tr style="{{ style }}">
				{% for col in row.values() %}
					<td>{{ col }}</td>
				{% endfor %}
			</tr>
		{% endfor %}
	</tbody>
</table""",
            skel={
                "name": self.name,
                "header": header,
                "body": body,
            },
            extraFiles=[("report.csv", io.read())],
        )

    def __enter__(self):
        self._read()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.flush()
