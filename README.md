This project relies heavily on https://gitlab.com/aeberhardt/stashcat-api-client, so a huge 
kudos to Anselm.

We are based on TurboGears2, calling main.py will start a webserver on 127.0.0.1:8080 (you may
specify the port using command line arguments) with endpoints to interact with hermine.

Important Note with GroupAlarm-Endpoints: The constructed URLs will contain sensitive
information in the request-line, which could get logged. Sadly this is needed as GroupAlarm-
Flows do not allow complex operations such as Combining JSON-objects. To increase security
for all users of this service, please disable all Access-Logs on any Proxys.
