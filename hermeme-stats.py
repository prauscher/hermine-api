#!/usr/bin/env python3

import sys
from datetime import datetime, timedelta
from collections import defaultdict
from api_client import StashCatClient


if len(sys.argv) <= 3:
    print(f"Usage: {sys.argv[0]} MAIL ACCOUNT_PASS ENCRYPTION_PASS")
    sys.exit(10)

client = StashCatClient()
client.login(sys.argv[1], sys.argv[2])
client.open_private_key(sys.argv[3])

for channel in client.get_channels(client.get_companies()[0]["id"]):
    if channel["name"] == "A_THW_HerMEME":
        channel_id = channel["id"]
        break
else:
    print("Unknown channel")
    sys.exit(1)

users = defaultdict(lambda: {"posts": 0, "likes": 0, "replies": 0})
msg_authors = {}
msg_replies = defaultdict(lambda: 0)

offset = 0
while True:
    seen = False
    for msg in client.get_messages(("channel", channel_id), offset=offset):
        if datetime.now() - datetime.fromtimestamp(int(msg["time"])) > timedelta(days=7):
            break

        offset += 1
        seen = True

        if msg["text"] is None:
            # message deleted
            continue

        username = f"{msg['sender']['first_name']} {msg['sender']['last_name']}"
        users[username]["posts"] += 1
        users[username]["likes"] += msg.get('likes', 0)

        msg_authors[msg["id"]] = username
        if msg.get("reply_to", None) is not None:
            if isinstance(msg["reply_to"], int):
                msg_replies[msg["reply_to"]] += 1
            elif isinstance(msg["reply_to"], dict):
                msg_replies[msg["reply_to"]["message_id"]] += 1
    else:
        if seen:
            continue

    break

for msg_id, author in msg_authors.items():
    users[author]["replies"] += msg_replies[msg_id]


users = sorted(users.items(), key=lambda item: (item[1]["likes"] / item[1]["posts"], item[1]["posts"], item[1]["likes"], item[1]["replies"]), reverse=True)
print(f"{'User':<40} {'Like/Posts':>10} {'Posts':>10} {'Likes':>10} {'Antworten':>10}")
for user, stats in users:
    if len(user) > 37:
       user = f"{user[0:37]}..."
    print(f"{user:<40}   {stats['likes'] / stats['posts']:8.4f} {stats['posts']:>10} {stats['likes']:>10} {stats['replies']:>10}")
