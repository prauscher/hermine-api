#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from tg import expose, decode_params, TGController, request
from tempfile import TemporaryDirectory
import hashlib
import json

from api_client import StashCatClient


account_dir = TemporaryDirectory()


# Note: **kw is needed somehow to trick TurboGears-decode_params
class HermineController(TGController):
    @expose("json")
    @decode_params("json")
    def login(self, *, mail, password, **kw):
        client = StashCatClient()
        payload = client.login(mail, password)
        if payload:
            return {"user_id": payload["userinfo"]["id"],
                    "client_key": payload["client_key"]}
        else:
            return {"error": "login failed"}

    @expose("json")
    @decode_params("json")
    def subscribed_channels(self, *, user_id, client_key, **kw):
        client = StashCatClient(client_key, user_id)
        return {"channels":
            [{k: v for k, v in channel.items() if k in ["id", "name", "description", "image", "type", "visible", "last_action", "last_activity", "favourite", "manager", "user_count", "unread"]}
             for channel in client.get_channels()]
        }

    @expose("json")
    @decode_params("json")
    def send_channel(self, *, user_id, client_key, channel_name, encryption_key, message, **kw):
        client = StashCatClient(client_key, user_id)
        client.open_private_key(encryption_key)
        channel_dict = next(filter(
            lambda chan_dict: chan_dict["name"] == channel_name,
            client.get_channels()))
        client.send_msg(("channel", channel_dict["id"]), message)
        return {"status": "ok"}

    @expose("json")
    @decode_params("json")
    def send_conversation(self, *, user_id, client_key, encryption_key, names, message, **kw):
        client = StashCatClient(client_key, user_id)
        client.open_private_key(encryption_key)
        receivers = []
        for name in names:
            results = client.search_user(name)
            if len(results) != 1:
                return {"error": f"Name {name} does not match exactly one user"}
            receivers.append(results[0])
        conversation = client.open_conversation(receivers)
        client.send_msg(("conversation", conversation["id"]), message)
        return {"status": "ok"}

    @expose("json")
    def ga_action(self, mail, password, encryption_key, *receiver, **kw):
        account_filename = f"{account_dir.name}/{hashlib.sha256(mail.encode('utf-8')).hexdigest()}"
        try:
            account_data = json.loads(open(account_filename, 'r', encoding='utf-8').read())
            client = StashCatClient(account_data['client_key'], account_data['user_id'])
            client.open_private_key(encryption_key)
        except (OSError, ValueError):
            client = StashCatClient()
            payload = client.login(mail, password)
            if payload:
                open(account_filename, 'w', encoding='utf-8').write(
                    json.dumps({'user_id': payload['userinfo']['id'],
                                'client_key': payload['client_key']}))
            else:
                return {'error': 'Login failed'}
            client.open_private_key(encryption_key)

        if not receiver:
            return {"status": "ok", "text": "login successful"}

        if receiver[0] == "user":
            receivers = []
            for name in receiver[1:]:
                results = client.search_user(name)
                if len(results) != 1:
                    return {"error": f"Name {name} does not match exactly one user"}
                receivers.append(results[0])
            conversation = client.open_conversation(receivers)
            client.send_msg(("conversation", conversation["id"]), request.body.decode("utf-8"))

        elif receiver[0] == "chan":
            channel_dict = next(filter(
                lambda chan_dict: chan_dict["name"] == receiver[1],
                client.get_channels()))
            client.send_msg(("channel", channel_dict["id"]), request.body.decode("utf-8"))
        else:
            channel_dict = next(filter(
                lambda chan_dict: chan_dict["name"] == receiver[0],
                client.get_channels()))
            client.send_msg(("channel", channel_dict["id"]), request.body.decode("utf-8"))

        return {"status": "ok"}

    @expose(content_type="text/plain")
    @decode_params("json")
    def ga_alarmiert_text(self, *, scenarios, units, labels, users, **kw):
        alarmiert = []
        for scenario in scenarios:
            alarmiert.extend([unit["name"] for unit in scenario["units"]])
        alarmiert.extend([unit["name"] for unit in units])
        for label in labels:
            if label["amount"] > 0:
                alarmiert.append("{}x {}".format(label["amount"], label["label"]["name"]))
            else:
                alarmiert.append(label["label"]["name"])
        alarmiert.extend(["User #{}".format(user) for user in users])
        return ", ".join(alarmiert)

    @expose()
    def index(self):
        return "Work in progress"
