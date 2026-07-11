import httpx

from api.config import settings

BASE_URL = f"http://{settings.host}:{settings.port}"


def post(path: str, json: dict) -> dict:
    with httpx.Client(base_url=BASE_URL, timeout=600) as client:
        response = client.post(path, json=json)
        response.raise_for_status()
        return response.json()
