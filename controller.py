#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from tg import expose, decode_params, TGController, request

from api_client import StashCatClient


class HermineController(TGController):
    @expose("json")
    @decode_params("json")
    def login(self, *a, mail, password, **kw):
        client = StashCatClient()
        payload = client.login(mail, password)
        if payload:
            return {"user_id": payload["userinfo"]["id"],
                    "client_key": payload["client_key"]}
        else:
            return {"error": "login failed"}

    @expose("json")
    @decode_params("json")
    def subscribed_channels(self, *a, user_id, client_key, **kw):
        client = StashCatClient(client_key, user_id)
        client.get_channels()
        return {"channels":
            [{k: v for k, v in channel.items() if k in ["id", "name", "description", "image", "type", "visible", "last_action", "last_activity", "favourite", "manager", "user_count", "unread"]}
             for channel in client.subscribed_channels.values()]
        }

    @expose("json")
    @decode_params("json")
    def send_channel(self, *a, user_id, client_key, channel_name, encryption_key, message, **kw):
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
    def ga_send_channel(self, user_id, client_key, encryption_key, channel_name, *a, **kw):
        client = StashCatClient(client_key, user_id)
        client.get_private_key()
        client.unlock_private_key(encryption_key)
        client.get_channels()
        channel_dict = next(filter(
            lambda chan_dict: chan_dict["name"] == channel_name,
            client.subscribed_channels.values()))
        client.send_msg_to_channel(channel_dict["id"], request.body)
        return {"status": "ok"}

    @expose()
    def index(self):
        return "Work in progress"
