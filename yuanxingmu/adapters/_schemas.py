"""Shared strict argument schemas, imported only with an optional native SDK."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EmptyArgs(ClosedModel):
    pass


class ReadArgs(ClosedModel):
    resource: StrictStr


class SendArgs(ClosedModel):
    destination: StrictStr
    body: StrictStr


class EmailDraft(ClosedModel):
    recipient: StrictStr
    subject: StrictStr
    body: StrictStr


class DraftEmailArgs(ClosedModel):
    draft: EmailDraft


class MessagePayload(ClosedModel):
    body: StrictStr


class UploadPayload(ClosedModel):
    filename: StrictStr
    content: StrictStr


class ContentPayload(ClosedModel):
    content: StrictStr


class FormField(ClosedModel):
    name: StrictStr
    value: StrictStr


class FormPayload(ClosedModel):
    fields: list[FormField] = Field(max_length=64)


class MessageProposal(ClosedModel):
    kind: Literal["message"]
    target_id: StrictStr
    payload: MessagePayload


class UploadProposal(ClosedModel):
    kind: Literal["upload"]
    target_id: StrictStr
    payload: UploadPayload


class FormProposal(ClosedModel):
    kind: Literal["form"]
    target_id: StrictStr
    payload: FormPayload


class OverwriteProposal(ClosedModel):
    kind: Literal["overwrite"]
    target_id: StrictStr
    payload: ContentPayload


class DeleteProposal(ClosedModel):
    kind: Literal["delete"]
    target_id: StrictStr
    payload: EmptyArgs


ActionProposal = MessageProposal | UploadProposal | FormProposal | OverwriteProposal | DeleteProposal


class ProposeActionArgs(ClosedModel):
    proposal: ActionProposal


SCHEMAS = {"read": ReadArgs, "send": SendArgs, "describe": EmptyArgs, "action_targets": EmptyArgs,
           "propose_action": ProposeActionArgs, "draft_email": DraftEmailArgs}
