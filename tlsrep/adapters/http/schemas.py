"""Request bodies for the HTTP adapter — the only Pydantic in the stack.

These live at the framework boundary. The application layer speaks plain
strings and lists; FastAPI validates the wire into these models and hands the
raw fields to a `UseCases` method.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

# A ClientHello above this is not a ClientHello. A single TLS record maxes at
# 16 KiB of payload plus the 5-byte header; a base64 body a few times that is
# already generous and caps abuse.
_MAX_HELLO_B64 = 65536

# The record layer caps a single record at 16 KiB and a collector never needs
# to submit more than this many hellos in one call.
_MAX_BATCH = 5000


class ClientHelloIn(BaseModel):
    client_hello: str = Field(
        ...,
        max_length=_MAX_HELLO_B64,
        description="base64-encoded raw TLS ClientHello record",
    )


class IngestBatch(BaseModel):
    data: list[str] = Field(..., max_length=_MAX_BATCH)
