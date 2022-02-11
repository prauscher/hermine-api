#!/usr/bin/env python3
# Taken with huge appreciation from https://gitlab.com/aeberhardt/stashcat-api-client

import argparse
import base64
import http.client
import json
import logging

import requests

import Crypto.PublicKey.RSA
import Crypto.Cipher
import Crypto.Cipher.PKCS1_OAEP
import Crypto.Cipher.AES
import Crypto.Random
import Crypto.Util.Padding


class StashCatClient:
    base_url = "https://api.thw-messenger.de"
    stashcat_version = "3.19.1"
    device_id = "stashcatiskindofbrokenrandomstr1"

    headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.5",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0",
    }

    client_key = None
    user_id = None
    private_encrypted_key = None
    private_key = None
    public_key = None

    company_id = None

    conversations = {}
    subscribed_channels = {}

    def __init__(self, client_key=None, user_id=None):
        if client_key and user_id:
            self.client_key = client_key
            self.user_id = user_id

    def login(self, username, password):
        payload = {
            "email": username,
            "password": password,
            "device_id": self.device_id,
            "app_name": "hermine@thw-Firefox:82.0-browser-%s" % self.stashcat_version,
            "encrypted": True,
            "callable": True,
        }

        r = requests.post(
            "%s/auth/login" % self.base_url, data=payload, headers=self.headers
        )
        r.raise_for_status()

        data = r.json()

        if data["status"]["value"] == "OK":
            self.client_key = data["payload"]["client_key"]
            self.user_id = data["payload"]["userinfo"]["id"]
            return data["payload"]
        else:
            logging.debug(json.dumps(data, indent=2))
            return None

    def get_private_key(self):
        payload = {"client_key": self.client_key, "device_id": self.device_id}
        r = requests.post(
            "%s/security/get_private_key" % self.base_url,
            data=payload,
            headers=self.headers,
        )
        r.raise_for_status()

        data = r.json()
        if data["status"]["value"] == "OK":
            private_key_field = json.loads(data["payload"]["keys"]["private_key"])
            # there might be an unescaping bug here....
            self.private_encrypted_key = private_key_field["private"]
            self.public_key = data["payload"]["keys"]["public_key"]
            return data["payload"]
        else:
            logging.debug(json.dumps(data, indent=2))
            return None

    def unlock_private_key(self, encryption_password):
        self.private_key = Crypto.PublicKey.RSA.import_key(
            self.private_encrypted_key, passphrase=encryption_password
        )
        self.public_key = self.private_key.publickey()

    def send_check(self):
        payload = {"client_key": self.client_key, "device_id": self.device_id}
        r = requests.post(
            "%s/security/get_private_key" % self.base_url,
            data=payload,
            headers=self.headers,
        )
        r.raise_for_status()

    def get_open_conversations(self):
        payload = {
            "client_key": self.client_key,
            "device_id": self.device_id,
            "limit": 30,
            "offset": 0,
            "archive": 0,
        }
        r = requests.post(
            "%s/message/conversations" % self.base_url,
            data=payload,
            headers=self.headers,
        )
        r.raise_for_status()

        data = r.json()
        if data["status"]["value"] != "OK":
            logging.debug(json.dumps(data, indent=2))
            return None

        self.conversations = {x["id"]: x for x in data["payload"]["conversations"]}

    def search_user(self, search):
        payload = {
            "client_key": self.client_key,
            "device_id": self.device_id,
            "company": self.company_id,
            "limit": 50,
            "offset": 0,
            "key_hashes": False,
            "search": search,
            "sorting": ["first_name_asc", "last_name_asc"],
            "exclude_user_ids": [],
            "group_ids": [],
        }
        r = requests.post(
            "%s/users/listing" % self.base_url,
            data=payload,
            headers=self.headers,
        )
        r.raise_for_status()

        data = r.json()
        if data["status"]["value"] != "OK":
            logging.debug(json.dumps(data, indent=2))
            return None

        return data["payload"]["users"]

    def open_conversation(self, members):
        conversation_key = Crypto.Random.get_random_bytes(32)

        receivers = []
        # Always add ourselves
        receivers.append({
            "id": int(self.user_id),
            "key": base64.b64encode(Crypto.Cipher.PKCS1_OAEP.new(self.public_key).encrypt(conversation_key)).decode("utf-8")
        })
        for member in members:
            pubkey = Crypto.PublicKey.RSA.import_key(member["public_key"])
            encryptor = Crypto.Cipher.PKCS1_OAEP.new(pubkey)
            receivers.append({
                "id": int(member["id"]),
                "key": base64.b64encode(encryptor.encrypt(conversation_key)).decode("utf-8")
            })

        payload = {
            "client_key": self.client_key,
            "device_id": self.device_id,
            "members": json.dumps(receivers),
        }
        print(payload)
        r = requests.post(
            "%s/message/createEncryptedConversation" % self.base_url,
            data=payload,
            headers=self.headers,
        )
        r.raise_for_status()

        data = r.json()
        if data["status"]["value"] != "OK":
            print(data)
            logging.debug(json.dumps(data, indent=2))
            return None

        conversation = data["payload"]["conversation"]
        self.conversations[conversation["id"]] = conversation
        return conversation

    def get_company_member(self):
        payload = {
            "client_key": self.client_key,
            "device_id": self.device_id,
            "no_cache": True,
        }
        r = requests.post(
            "%s/company/member" % self.base_url, data=payload, headers=self.headers
        )
        r.raise_for_status()

        data = r.json()
        if data["status"]["value"] != "OK":
            logging.debug(json.dumps(data, indent=2))
            return None

        self.company_id = data["payload"]["companies"][0]["id"]

    def get_channels(self):
        self.get_company_member()
        payload = {
            "client_key": self.client_key,
            "device_id": self.device_id,
            "company": self.company_id,
        }
        r = requests.post(
            "%s/channels/subscripted" % self.base_url,
            data=payload,
            headers=self.headers,
        )
        r.raise_for_status()

        data = r.json()
        if data["status"]["value"] != "OK":
            logging.debug(json.dumps(data, indent=2))
            return None

        self.subscribed_channels = {x["id"]: x for x in data["payload"]["channels"]}

    def send_msg_to_channel(self, channel_id, message):
        conversation_key = self.subscribed_channels[channel_id]["key"]
        decoded_conversation_key = base64.b64decode(conversation_key)
        decryptor = Crypto.Cipher.PKCS1_OAEP.new(self.private_key)
        conversation_key = decryptor.decrypt(decoded_conversation_key)

        cipher = Crypto.Cipher.AES.new(conversation_key, Crypto.Cipher.AES.MODE_CBC)

        ct_bytes = cipher.encrypt(
            Crypto.Util.Padding.pad(
                message.encode("utf-8"), Crypto.Cipher.AES.block_size
            )
        )
        iv = cipher.iv.hex()
        ct = ct_bytes.hex()
        verification = ""
        payload = {
            "client_key": self.client_key,
            "device_id": self.device_id,
            "target": "channel",
            "channel_id": channel_id,
            "text": ct,
            "iv": iv,
            "files": "[]",
            "url": "[]",
            "type": "text",
            "verification": verification,
            "encrypted": True,
        }
        r = requests.post(
            "%s/message/send" % self.base_url, data=payload, headers=self.headers
        )
        r.raise_for_status()

        data = r.json()
        logging.debug(json.dumps(data, indent=2))

    def send_msg_to_user(self, conversation_id, message, encrypt=False):
        if encrypt:
            conversation_key = self.conversations[conversation_id]["key"]
            decoded_conversation_key = base64.b64decode(conversation_key)
            decryptor = Crypto.Cipher.PKCS1_OAEP.new(self.private_key)
            conversation_key = decryptor.decrypt(decoded_conversation_key)

            cipher = Crypto.Cipher.AES.new(conversation_key, Crypto.Cipher.AES.MODE_CBC)

            ct_bytes = cipher.encrypt(
                Crypto.Util.Padding.pad(
                    message.encode("utf-8"), Crypto.Cipher.AES.block_size
                )
            )
            iv = cipher.iv.hex()
            ct = ct_bytes.hex()
            verification = ""
            payload = {
                "client_key": self.client_key,
                "device_id": self.device_id,
                "target": "conversation",
                "conversation_id": conversation_id,
                "text": ct,
                "iv": iv,
                "files": "[]",
                "url": "[]",
                "type": "text",
                "verification": verification,
                "encrypted": True,
            }
        else:
            payload = {
                "client_key": self.client_key,
                "device_id": self.device_id,
                "target": "conversation",
                "conversation_id": conversation_id,
                "text": message,
                "files": [],
                "url": [],
                "type": "text",
                "encrypted": False,
            }
        r = requests.post(
            "%s/message/send" % self.base_url, data=payload, headers=self.headers
        )
        r.raise_for_status()

        data = r.json()
        logging.debug(json.dumps(data, indent=2))

    def startup(self, encryption_key):
        if not self.client_key or not self.user_id:
            logging.error("Missing client_key OR user_id")
            return

        self.get_private_key()
        self.unlock_private_key(encryption_key)
        self.get_open_conversations()
        self.get_channels()


def setup_logging(debug=False):
    logging.basicConfig()
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.propagate = True

    if debug:
        loglevel = logging.DEBUG
        http.client.HTTPConnection.debuglevel = 1
    else:
        loglevel = logging.INFO

    logging.getLogger().setLevel(loglevel)
    requests_log.setLevel(loglevel)


def main():
    argp = argparse.ArgumentParser()
    argp.add_argument("username")
    argp.add_argument("password")
    argp.add_argument("encryption_key")
    argp.add_argument("--debug", action="store_true", default=False)
    args = argp.parse_args()

    setup_logging(args.debug)

    client = StashCatClient()
    payload = client.login(args.username, args.password)
    if not payload:
        return

    client.get_private_key()
    client.unlock_private_key(args.encryption_key)


if __name__ == "__main__":
    main()
