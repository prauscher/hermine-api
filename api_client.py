#!/usr/bin/env python3
# Taken with huge appreciation from https://gitlab.com/aeberhardt/stashcat-api-client
# Extended by prauscher

import argparse
import base64
import http.client
import json
import logging
import uuid

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

    _key_cache = {}

    def __init__(self, client_key=None, user_id=None):
        if client_key and user_id:
            self.client_key = client_key
            self.user_id = user_id

    def login(self, username, password):
        payload = {
            "email": username,
            "password": password,
            "device_id": self.device_id,
            "app_name": f"hermine@thw-Firefox:82.0-browser-{self.stashcat_version}",
            "encrypted": True,
            "callable": True,
        }

        r = requests.post(
            f"{self.base_url}/auth/login", data=payload, headers=self.headers
        )
        r.raise_for_status()

        data = r.json()

        if data["status"]["value"] != "OK":
            raise ValueError(data["status"]["message"])

        self.client_key = data["payload"]["client_key"]
        self.user_id = data["payload"]["userinfo"]["id"]
        return data["payload"]

    def get_private_key(self):
        payload = {"client_key": self.client_key, "device_id": self.device_id}
        r = requests.post(
            f"{self.base_url}/security/get_private_key",
            data=payload,
            headers=self.headers,
        )
        r.raise_for_status()

        data = r.json()
        if data["status"]["value"] != "OK":
            raise ValueError(data["status"]["message"])

        private_key_field = json.loads(data["payload"]["keys"]["private_key"])
        # there might be an unescaping bug here....
        self.private_encrypted_key = private_key_field["private"]
        self.public_key = data["payload"]["keys"]["public_key"]
        return data["payload"]

    def unlock_private_key(self, encryption_password):
        self.private_key = Crypto.PublicKey.RSA.import_key(
            self.private_encrypted_key, passphrase=encryption_password
        )
        self.public_key = self.private_key.publickey()

    def send_check(self):
        payload = {"client_key": self.client_key, "device_id": self.device_id}
        r = requests.post(
            f"{self.base_url}/security/get_private_key",
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
            f"{self.base_url}/message/conversations",
            data=payload,
            headers=self.headers,
        )
        r.raise_for_status()

        data = r.json()
        if data["status"]["value"] != "OK":
            raise ValueError(data["status"]["message"])

        return data["payload"]["conversations"]

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
            f"{self.base_url}/users/listing",
            data=payload,
            headers=self.headers,
        )
        r.raise_for_status()

        data = r.json()
        if data["status"]["value"] != "OK":
            raise ValueError(data["status"]["message"])

        return data["payload"]["users"]

    def open_conversation(self, members):
        conversation_key = Crypto.Random.get_random_bytes(32)

        receivers = []
        # Always add ourselves
        encryptor = Crypto.Cipher.PKCS1_OAEP.new(self.public_key)
        receivers.append({
            "id": int(self.user_id),
            "key": base64.b64encode(encryptor.encrypt(conversation_key)).decode("utf-8")
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
        r = requests.post(
            f"{self.base_url}/message/createEncryptedConversation",
            data=payload,
            headers=self.headers,
        )
        r.raise_for_status()

        data = r.json()
        if data["status"]["value"] != "OK":
            raise ValueError(data["status"]["message"])

        conversation = data["payload"]["conversation"]
        self._key_cache[("conversation", conversation["id"])] = conversation["key"]
        return conversation

    def get_messages(self, source):
        payload = {
            "client_key": self.client_key,
            "device_id": self.device_id,
            f"{source[0]}_id": source[1],
            "source": source[0],
            "limit": 30,
            "offset": 0,
        }
        r = requests.post(
            f"{self.base_url}/message/content",
            data=payload,
            headers=self.headers,
        )
        r.raise_for_status()

        data = r.json()
        if data["status"]["value"] != "OK":
            raise ValueError(data["status"]["message"])

        conversation_key = self._get_conversation_key(source)

        for message in data["payload"]["messages"]:
            if message["kind"] == "message" and message["encrypted"]:
                cipher = Crypto.Cipher.AES.new(
                    conversation_key,
                    Crypto.Cipher.AES.MODE_CBC,
                    iv=bytes.fromhex(message["iv"])
                )

                pt_bytes = Crypto.Util.Padding.unpad(
                    cipher.decrypt(bytes.fromhex(message["text"])),
                    Crypto.Cipher.AES.block_size
                )
                message["text_decrypted"] = pt_bytes.decode("utf-8")

                if message["location"]["encrypted"]:
                    cipher_lat = Crypto.Cipher.AES.new(
                        conversation_key,
                        Crypto.Cipher.AES.MODE_CBC,
                        iv=bytes.fromhex(message["location"]["iv"])
                    )
                    message["location"]["latitude_decrypted"] = Crypto.Util.Padding.unpad(
                        cipher_lat.decrypt(bytes.fromhex(message["location"]["latitude"])),
                        Crypto.Cipher.AES.block_size
                    ).decode("utf-8")

                    cipher_lon = Crypto.Cipher.AES.new(
                        conversation_key,
                        Crypto.Cipher.AES.MODE_CBC,
                        iv=bytes.fromhex(message["location"]["iv"])
                    )
                    message["location"]["longitude_decrypted"] = Crypto.Util.Padding.unpad(
                        cipher_lon.decrypt(bytes.fromhex(message["location"]["longitude"])),
                        Crypto.Cipher.AES.block_size
                    ).decode("utf-8")
            yield message

    def get_company_member(self):
        payload = {
            "client_key": self.client_key,
            "device_id": self.device_id,
            "no_cache": True,
        }
        r = requests.post(
            f"{self.base_url}/company/member", data=payload, headers=self.headers
        )
        r.raise_for_status()

        data = r.json()
        if data["status"]["value"] != "OK":
            raise ValueError(data["status"]["message"])

        return data["payload"]["companies"][0]["id"]

    def get_channels(self):
        self.get_company_member()
        payload = {
            "client_key": self.client_key,
            "device_id": self.device_id,
            "company": self.company_id,
        }
        r = requests.post(
            f"{self.base_url}/channels/subscripted",
            data=payload,
            headers=self.headers,
        )
        r.raise_for_status()

        data = r.json()
        if data["status"]["value"] != "OK":
            raise ValueError(data["status"]["message"])

        return data["payload"]["channels"]

    def _get_conversation_key(self, target):
        try:
            encrypted_key = self._key_cache[target]
        except KeyError:
            if target[0] == "conversation":
                r = requests.post(
                    f"{self.base_url}/message/conversation",
                    data={
                        "client_key": self.client_key,
                        "device_id": self.device_id,
                        "conversation_id": target[1]
                    },
                    headers=self.headers,
                )
                r.raise_for_status()
                data = r.json()
                if data["status"]["value"] != "OK":
                    raise ValueError(r["status"]["message"]) from None
                encrypted_key = data["payload"]["conversation"]["key"]
            elif target[0] == "channel":
                r = requests.post(
                    f"{self.base_url}/channels/info",
                    data={
                        "client_key": self.client_key,
                        "device_id": self.device_id,
                        "channel_id": target[1],
                        "without_members": True
                    },
                    headers=self.headers,
                )
                r.raise_for_status()
                data = r.json()
                if data["status"]["value"] != "OK":
                    raise ValueError(r["status"]["message"]) from None
                encrypted_key = data["payload"]["channels"]["key"]
            else:
                raise AttributeError from None

            self._key_cache[target] = encrypted_key

        decryptor = Crypto.Cipher.PKCS1_OAEP.new(self.private_key)
        return decryptor.decrypt(base64.b64decode(encrypted_key))

    def send_msg(self, target, message, *, files=None):
        files = files or []

        conversation_key = self._get_conversation_key(target)
        cipher = Crypto.Cipher.AES.new(conversation_key, Crypto.Cipher.AES.MODE_CBC)

        ct_bytes = cipher.encrypt(
            Crypto.Util.Padding.pad(
                message.encode("utf-8"), Crypto.Cipher.AES.block_size
            )
        )
        r = requests.post(
            f"{self.base_url}/message/send",
            data={
                "client_key": self.client_key,
                "device_id": self.device_id,
                "target": target[0],
                f"{target[0]}_id": target[1],
                "text": ct_bytes.hex(),
                "iv": cipher.iv.hex(),
                "files": json.dumps(files),
                "url": "[]",
                "type": "text",
                "verification": "",
                "encrypted": True,
            },
            headers=self.headers
        )
        r.raise_for_status()

        return r.json()["payload"]["message"]

    def send_msg_to_channel(self, channel_id, message):
        return self.send_msg(("channel", channel_id), message)

    def send_msg_to_user(self, conversation_id, message):
        return self.send_msg(("conversation", conversation_id), message)

    def upload_file(self, target, file, filename, content_type="application/octet-stream", *,
                    media_size=None):
        media_size = media_size or (None, None)
        cipher_conv = Crypto.Cipher.AES.new(
            self._get_conversation_key(target),
            Crypto.Cipher.AES.MODE_CBC
        )

        file_key = Crypto.Random.get_random_bytes(32)
        cipher_file = Crypto.Cipher.AES.new(file_key, Crypto.Cipher.AES.MODE_CBC)

        content = file.read()
        chunk_size = 5 * 1024 * 1024
        nr = 0
        upload_uuid = str(uuid.uuid4())
        for nr in range(0, len(content), chunk_size):
            chunk = content[nr * chunk_size:(nr + 1) * chunk_size]
            ct_bytes = cipher_file.encrypt(
                Crypto.Util.Padding.pad(
                    chunk,
                    Crypto.Cipher.AES.block_size
                )
            )

            r = requests.post(
                f"{self.base_url}/file/upload",
                data={
                    "resumableChunkNumber": nr,
                    "resumableChunkSize": chunk_size,
                    "resumableCurrentChunkSize": len(ct_bytes),
                    "resumableTotalSize": len(content),
                    "resumableType": content_type,
                    "resumableIdentifier": upload_uuid,
                    "resumableFilename": filename,
                    "resumableRelativePath": filename,
                    "resumableTotalChunks": -(len(content) // -chunk_size),
                    "folder": 0,
                    "type": target[0],
                    "type_id": target[1],
                    "encrypted": True,
                    "iv": cipher_file.iv.hex(),
                    "media_width": media_size[0],
                    "media_height": media_size[1],
                    "client_key": self.client_key,
                   "device_id": self.device_id,
                },
                files={"file": ("[object Object]", ct_bytes, "application/octet-stream")},
                headers=self.headers,
            )
            r.raise_for_status()
            file_data = r.json()["payload"]["file"]

        ct_bytes = cipher_conv.encrypt(
            Crypto.Util.Padding.pad(file_key, Crypto.Cipher.AES.block_size)
        )
        r = requests.post(
            f"{self.base_url}/security/set_file_access_key",
            data={
                "client_key": self.client_key,
                "device_id": self.device_id,
                "file_id": file_data["id"],
                "target": target[0],
                "target_id": target[1],
                "key": ct_bytes.hex(),
                "iv": cipher_conv.iv.hex(),
            },
            headers=self.headers,
        )
        r.raise_for_status()
        return file_data


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
