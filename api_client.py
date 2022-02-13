#!/usr/bin/env python3
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

    _key_cache = {}

    def __init__(self, client_key=None, user_id=None):
        if client_key and user_id:
            self.client_key = client_key
            self.user_id = user_id

    def _post(self, url, *, data, include_auth=True, **kwargs):
        data["device_id"] = self.device_id
        if include_auth:
            data["client_key"] = self.client_key

        response = requests.post(f"{self.base_url}/{url}", data=data, headers=self.headers,
                                 **kwargs)
        response.raise_for_status()
        data = response.json()
        if data["status"]["value"] != "OK":
            raise ValueError(data["status"]["message"])
        return data["payload"]

    def login(self, username, password):
        data = self._post("auth/login", data={
            "email": username,
            "password": password,
            "app_name": f"hermine@thw-Firefox:82.0-browser-{self.stashcat_version}",
            "encrypted": True,
            "callable": True,
        })

        self.client_key = data["client_key"]
        self.user_id = data["userinfo"]["id"]
        return data

    def get_private_key(self):
        data = self._post("security/get_private_key", data={})
        private_key_field = json.loads(data["keys"]["private_key"])
        # there might be an unescaping bug here....
        self.private_encrypted_key = private_key_field["private"]
        self.public_key = data["keys"]["public_key"]
        return data

    def unlock_private_key(self, encryption_password):
        self.private_key = Crypto.PublicKey.RSA.import_key(
            self.private_encrypted_key, passphrase=encryption_password
        )
        self.public_key = self.private_key.publickey()

    def get_open_conversations(self):
        data = self._post("message/conversations", data={
            "limit": 30,
            "offset": 0,
            "archive": 0,
        })
        return data["conversations"]

    def search_user(self, search):
        data = self._post("users/listing", data={
            "client_key": self.client_key,
            "device_id": self.device_id,
            "limit": 50,
            "offset": 0,
            "key_hashes": False,
            "search": search,
            "sorting": ["first_name_asc", "last_name_asc"],
            "exclude_user_ids": [],
            "group_ids": [],
        })
        return data["users"]

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

        data = self._post("message/createEncryptedConversation", data={
            "members": json.dumps(receivers),
        })
        conversation = data["conversation"]
        self._key_cache[("conversation", conversation["id"])] = conversation["key"]
        return conversation

    def get_messages(self, source, limit=30, offset=0):
        data = self._post("message/content", data={
            f"{source[0]}_id": source[1],
            "source": source[0],
            "limit": limit,
            "offset": offset,
        })

        conversation_key = self._get_conversation_key(source)

        for message in data["messages"]:
            if message["kind"] == "message" and message["encrypted"]:
                message["text_decrypted"] = _decrypt_aes(
                    bytes.fromhex(message["text"]),
                    conversation_key,
                    bytes.fromhex(message["iv"])
                ).decode("utf-8")

                if message["location"]["encrypted"]:
                    message["location"]["latitude_decrypted"] = _decrypt_aes(
                        bytes.fromhex(message["location"]["latitude"]),
                        conversation_key,
                        bytes.fromhex(message["location"]["iv"])
                    ).decode("utf-8")
                    message["location"]["longitude_decrypted"] = _decrypt_aes(
                        bytes.fromhex(message["location"]["longitude"]),
                        conversation_key,
                        bytes.fromhex(message["location"]["iv"])
                    ).decode("utf-8")
            yield message

    def get_company_id(self):
        data = self._post("company/member", data={"no_cache": True})
        return data["companies"][0]["id"]

    def get_channels(self):
        data = self._post("channels/subscripted", data={"company": self.get_company_id()})
        return data["channels"]

    def _get_conversation_key(self, target):
        try:
            encrypted_key = self._key_cache[target]
        except KeyError:
            if target[0] == "conversation":
                data = self._post("message/conversation",
                                  data={"conversation_id": target[1]})
                encrypted_key = data["conversation"]["key"]
            elif target[0] == "channel":
                data = self._post("channels/info", data={
                    "channel_id": target[1],
                    "without_members": True
                })
                encrypted_key = data["channels"]["key"]
            else:
                raise AttributeError from None

            self._key_cache[target] = encrypted_key

        decryptor = Crypto.Cipher.PKCS1_OAEP.new(self.private_key)
        return decryptor.decrypt(base64.b64decode(encrypted_key))

    def send_msg(self, target, message, *, files=None, location=None):
        files = files or []

        iv = Crypto.Random.get_random_bytes(16)
        conversation_key = self._get_conversation_key(target)

        payload = {
            "client_key": self.client_key,
            "device_id": self.device_id,
            "target": target[0],
            f"{target[0]}_id": target[1],
            "text": _encrypt_aes(message.encode("utf-8"), conversation_key, iv).hex(),
            "iv": iv.hex(),
            "files": json.dumps(files),
            "url": "[]",
            "type": "text",
            "verification": "",
            "encrypted": True,
        }

        if location:
            payload["latitude"] = _encrypt_aes(
                str(location[0]).encode("utf-8"), conversation_key, iv).hex()
            payload["longitude"] = _encrypt_aes(
                str(location[1]).encode("utf-8"), conversation_key, iv).hex()

        return self._post("message/send", data=payload)["message"]

    def send_msg_to_channel(self, channel_id, message):
        return self.send_msg(("channel", channel_id), message)

    def send_msg_to_user(self, conversation_id, message):
        return self.send_msg(("conversation", conversation_id), message)

    def upload_file(self, target, file, filename, content_type="application/octet-stream", *,
                    media_size=None):
        media_size = media_size or (None, None)
        iv = Crypto.Random.get_random_bytes(16)
        file_key = Crypto.Random.get_random_bytes(32)
        conversation_key = self._get_conversation_key(target)

        content = file.read()
        chunk_size = 5 * 1024 * 1024
        nr = 0
        upload_uuid = str(uuid.uuid4())
        for nr in range(0, len(content), chunk_size):
            chunk = content[nr * chunk_size:(nr + 1) * chunk_size]
            ct_bytes = _encrypt_aes(
                chunk,
                file_key,
                iv
            )

            file_data = self._post("file/upload", data={
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
                "iv": iv.hex(),
                "media_width": media_size[0],
                "media_height": media_size[1],
            }, files={"file": ("[object Object]", ct_bytes, "application/octet-stream")})["file"]

        iv = Crypto.Random.get_random_bytes(16)
        self._post("security/set_file_access_key", data={
            "file_id": file_data["id"],
            "target": target[0],
            "target_id": target[1],
            "key": _encrypt_aes(file_key, conversation_key, iv).hex(),
            "iv": iv.hex(),
        })

        return file_data


def _encrypt_aes(plain: bytes, key: bytes, iv: bytes):
    return Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv=iv).encrypt(
        Crypto.Util.Padding.pad(plain, Crypto.Cipher.AES.block_size)
    )


def _decrypt_aes(cipher: bytes, key: bytes, iv: bytes):
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv=iv)
    return Crypto.Util.Padding.unpad(
        Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC).decrypt(cipher),
        Crypto.Cipher.AES.block_size
    )


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
