import csv
import io
import json
import logging
import typing as t
from datetime import datetime as dt
from types import TracebackType

from google.cloud.storage import Bucket

from viur.core import email
from viur.core.modules.file import GOOGLE_STORAGE_BUCKET

__all__ = ["Report"]

logger = logging.getLogger(__name__)

GOOGLE_STORAGE_BUCKET: Bucket = GOOGLE_STORAGE_BUCKET
"""Main GOOGLE_STORAGE_BUCKET (here reassigned to add the type hint)"""


class Report:
    """Reports are a kind of logging

    For example tasks in several there are information one want to save and
    finally send as mail to a person.

    .. code-block:: python

        from viur import toolkit

        with toolkit.Report("my_task_report") as report:
            # ... do something ...
            report.write(**{  # write some results
                "action": "update",
                "skel_key": "bar",
                "active": True,
            })
            # Not every entry must contain the same keys
            report.write(action="add", active=False)

        # In the last task batch send the mail
        with toolkit.Report("my_task_report") as report:
            report.send_as_mail("mail@me.com")
            report.delete()
    """

    __slots__ = ("name", "content", "columns", "changed")

    def __init__(self, name: str):
        self.name: str = name
        self.content: list[dict[str, t.Any]] = []
        self.columns: set = set()
        self.changed: bool = False

    @property
    def gsc_name(self) -> str:
        return "reports/report_{0}.json".format(self.name)

    def _read(self, raise_exc: bool = False) -> None:
        if (blob := GOOGLE_STORAGE_BUCKET.get_blob(self.gsc_name)) is None:
            if raise_exc:
                raise ValueError(f"GSC blob {self.gsc_name} not found")
            return None
        columns, content = json.loads(
            blob.download_as_bytes().decode("utf-8")
        )
        self.content = content
        self.columns = set(columns)

    def write(self, **value: t.Any) -> None:
        value["reportdate"] = dt.now().isoformat(" ", "seconds")
        self.content.append(value)
        self.columns.update(value.keys())
        self.changed = True

    def flush(self) -> None:
        if not self.changed:
            return
        value = (list(self.columns), self.content[:])
        GOOGLE_STORAGE_BUCKET.blob(self.gsc_name).upload_from_file(
            file_obj=io.BytesIO(json.dumps(value).encode()),
            content_type="application/json"
        )
        self.changed = False

    def read(self) -> list[dict[str, t.Any]]:
        self._read()
        return self.content

    def delete(self) -> None:
        # mark as not changed, so it won't be flushed
        self.changed = False
        try:
            GOOGLE_STORAGE_BUCKET.blob(self.gsc_name).delete()
        except AttributeError:  # already deleted
            logger.debug(self.gsc_name, exc_info=True)

    def send_as_mail(self, receiver: str | list[str]) -> bool:
        header = list(self.columns)
        body = [
            {key: entry.get(key) for key in header}
            for entry in self.content
        ]

        sio = io.StringIO()
        if self.content:
            writer = csv.DictWriter(sio, fieldnames=header)
            writer.writerows(self.content)
        else:
            sio.write("- no entries -")

        # noinspection PyTypeChecker
        return email.sendEMail(
            dests=receiver,
            # language=Jinja2
            stringTemplate="""Report {{ skel["name"] }}
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
</table>""",
            skel={
                "name": self.name,
                "header": header,
                "body": body,
            },
            attachments=[{
                "filename": "report.csv",
                "mimetype": "text/csv",
                "content": sio.getvalue().encode(),
            }],
        )

    def __enter__(self) -> t.Self:
        self._read()
        return self

    def __exit__(
        self,
        exc_type: t.Optional[t.Type[BaseException]],
        exc_val: t.Optional[BaseException],
        exc_tb: t.Optional[TracebackType],
    ) -> t.Literal[False]:
        self.flush()
        return False
