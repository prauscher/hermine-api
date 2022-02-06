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
        client.get_channels()
        return {"channels":
            [{k: v for k, v in channel.items() if k in ["id", "name", "description", "image", "type", "visible", "last_action", "last_activity", "favourite", "manager", "user_count", "unread"]}
             for channel in client.subscribed_channels.values()]
        }

    @expose("json")
    @decode_params("json")
    def send_channel(self, *, user_id, client_key, channel_name, encryption_key, message, **kw):
        client = StashCatClient(client_key, user_id)
        client.get_private_key()
        client.unlock_private_key(encryption_key)
        client.get_channels()
        channel_dict = next(filter(
            lambda chan_dict: chan_dict["name"] == channel_name,
            client.subscribed_channels.values()))
        client.send_msg_to_channel(channel_dict["id"], message)
        return {"status": "ok"}

    @expose("json")
    def ga_action(self, mail, password, encryption_key, channel_name=None, **kw):
        account_filename = f"{account_dir.name}/{hashlib.sha256(mail.encode('utf-8')).hexdigest()}"
        try:
            account_data = open(account_filename, 'r', encoding='utf-8').read()
            client = StashCatClient(account_data['client_key'], account_data['user_id'])
            if not client.get_private_key():
                raise OSError
        except OSError:
            client = StashCatClient()
            payload = client.login(mail, password)
            if payload:
                open(account_filename, 'w', encoding='utf-8').write(
                    json.dumps({'user_id': payload['userinfo']['id'],
                                'client_key': payload['client_key']}))
            else:
                return {'error': 'Login failed'}
            client.get_private_key()

        client.unlock_private_key(encryption_key)
        client.get_channels()
        if channel_name:
            channel_dict = next(filter(
                lambda chan_dict: chan_dict["name"] == channel_name,
                client.subscribed_channels.values()))
            client.send_msg_to_channel(channel_dict["id"], request.body.decode("utf-8"))
        return {"status": "ok"}

    @expose("json")
    def ga_send_channel(self, user_id, client_key, encryption_key, channel_name, **kw):
        client = StashCatClient(client_key, user_id)
        client.get_private_key()
        client.unlock_private_key(encryption_key)
        client.get_channels()
        channel_dict = next(filter(
            lambda chan_dict: chan_dict["name"] == channel_name,
            client.subscribed_channels.values()))
        client.send_msg_to_channel(channel_dict["id"], request.body.decode("utf-8"))
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
