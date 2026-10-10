import os
from dataclasses import dataclass

from dotenv import load_dotenv
from garminconnect import Garmin

from ._garmin_auth import TokenStore, authenticate


@dataclass(frozen=True)
class GarminConfiguration:
    activity_fetch_limit: int


def get_garmin_client() -> tuple[Garmin, GarminConfiguration]:
    load_dotenv()

    print("Initializing Garmin client...")

    garmin_client = _get_garmin_client()
    garmin_configuration = _get_garmin_configuration()

    print("Garmin client authenticated successfully.")

    return garmin_client, garmin_configuration


def _get_garmin_client() -> Garmin:
    store = TokenStore()
    token = store.load(os.getenv("GARMIN_AUTH_TOKEN"))
    return authenticate(token, store.save)


def _get_garmin_configuration():
    return GarminConfiguration(
        activity_fetch_limit=int(os.getenv("GARMIN_ACTIVITIES_FETCH_LIMIT", "10")),
    )
