#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from tg import expose, decode_params, TGController, request
from PIL import Image
from tempfile import TemporaryDirectory
import hashlib
import json

from api_client import StashCatClient


account_dir = TemporaryDirectory()


# Note: **kw is needed somehow to trick TurboGears-decode_params
class HermineController(TGController):
    def _get_client(self, mail, password):
        account_filename = f"{account_dir.name}/{hashlib.sha256(mail.encode('utf-8')).hexdigest()}"
        try:
            account_data = json.loads(open(account_filename, 'r', encoding='utf-8').read())
            client = StashCatClient(account_data['device_id'],
                                    account_data['client_key'],
                                    account_data['user_id'],
                                    account_data['hidden_id'])
            client.check()
        except (OSError, ValueError):
            client = StashCatClient()
            payload = client.login(mail, password)
            if not payload:
                raise ValueError

            open(account_filename, 'w', encoding='utf-8').write(
                 json.dumps({'user_id': client.user_id,
                             'client_key': client.client_key,
                             'device_id': client.device_id,
                             'hidden_id': client.hidden_id}))

        return client

    @expose("json")
    def ga_action(self, mail, password, encryption_key, *receiver, **kw):
        try:
            client = self._get_client(mail, password)
            client.open_private_key(encryption_key)
        except ValueError:
            return {'error': 'Login failed'}

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
            _send(client, conversation, request.body.decode("utf-8"))

        else:
            # allow explicit definition of channel
            if receiver[0] == "chan":
                receiver = receiver[1:]

            channels = [channel for company in client.get_companies() for channel in client.get_channels(company["id"])]
            channel_dict = next(filter(lambda chan_dict: chan_dict["name"] == receiver[0], channels))
            _send(client, channel_dict, request.body.decode("utf-8"))

        return {"status": "ok"}

    @expose("json")
    def send_channel_attachment(self, mail, password, encryption_key, *, channel_name, message, file=None, **kw):
        try:
            client = self._get_client(mail, password)
            client.open_private_key(encryption_key)
        except ValueError:
            return {'error': 'Login failed'}

        channels = [channel for company in client.get_companies() for channel in client.get_channels(company["id"])]
        channel_dict = next(filter(lambda chan_dict: chan_dict["name"] == channel_name, channels))
        file_ids = []
        if file is not None:
            media_size = None
            try:
                image = Image.open(file.file)
                media_size = (image.width, image.height)
            except IOError:
                pass
            file.file.seek(0)
            file_ids.append(client.upload_file(("channel", channel_dict["id"]), file.file, file.filename, file.type, media_size=media_size)["id"])
        _send(client, channel_dict, message, files=file_ids)
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


def _send(client, target, message, **kwargs):
    if "membership" in target:
        target_api = ("channel", target["id"])
        target_text = target["name"]
    elif "members" in target:
        target_api = ("conversation", target["id"])
        target_text = ", ".join(f"{member['first_name']} {member['last_name']}" for member in target["members"])
    else:
        return

    # T_ODAR_BotSpiegel
    client.send_msg(("channel", 180808), f"An {target_text}:\n{message}", **kwargs)
    client.send_msg(target_api, message, **kwargs)
