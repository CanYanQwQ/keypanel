import argparse
import os

from .client import CardKeyClient
from .transport_crypto import encrypt_card_key


def main() -> None:
    parser = argparse.ArgumentParser(description="Call CardKey API v1 with an encrypted card key")
    parser.add_argument("action", choices=("verify", "activate", "consume", "query", "unbind"))
    parser.add_argument("card_key")
    parser.add_argument("--device-id")
    parser.add_argument("--count", type=int)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    app_id = os.environ["CARDKEY_APP_ID"]
    app_secret = os.environ["CARDKEY_APP_SECRET"]
    client = CardKeyClient(os.environ["CARDKEY_BASE_URL"], app_id, app_secret)
    encrypted = encrypt_card_key(args.card_key, app_secret, app_id)
    common = {"card_key": encrypted, "device_id": args.device_id}
    if args.action == "verify": result = client.verify(**common)
    elif args.action == "activate": result = client.activate(**common)
    elif args.action == "consume": result = client.consume(**common, count=args.count)
    elif args.action == "query": result = client.query(**common)
    else: result = client.unbind(**common, force=args.force)
    print({"code": result.code, "message": result.message, "success": result.success, "server_time": result.server_time, "data": result.data})


if __name__ == "__main__":
    main()
