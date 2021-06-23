from fastapi import FastAPI, Response, status
import requests
import json
import os
app = FastAPI()
app.title = "Simple Kafka Client"
URL = os.getenv("KAFKA_REST")


@app.post("/produce", status_code=202)
async def produce(
    response: Response, topic: str = "acapy-inbound-test", payload: dict = {}
):
    headers = {"Content-Type": "application/vnd.kafka.json.v2+json"}

    data = json.dumps({"records": [{"value": payload}]})

    response = requests.post(f"{URL}/topics/{topic}", headers=headers, data=data)
    if not response.ok:
        response.status_code = status.HTTP_400_BAD_REQUEST
    return {"result": response.ok}


@app.get("/topics", status_code=200)
async def topics():
    response = requests.get(f"{URL}/topics")
    return {"result": response.json()}


@app.get("/consume", status_code=200)
async def consume(response: Response, topic: str = "acapy-outbound-test"):
    create_consumer()
    suscribe_topic(topic)
    records = consume()
    response = []
    for record in records:
        response.append(record.get("value"))

    close_consumer()

    return response


def create_consumer():
    headers = {"Content-Type": "application/vnd.kafka.json.v2+json"}

    data = json.dumps(
        {"name": "internal_consumer", "format": "json", "auto.offset.reset": "earliest"}
    )

    requests.post(f"{URL}/consumers/my_json_consumer", headers=headers, data=data)


def suscribe_topic(topic):
    headers = {"Content-Type": "application/vnd.kafka.json.v2+json"}

    data = json.dumps({"topics": [topic]})
    requests.post(
        f"{URL}/consumers/my_json_consumer/instances/internal_consumer/subscription",
        headers=headers,
        data=data,
    )


def consume():
    headers = {
        "Accept": "application/vnd.kafka.json.v2+json",
    }
    cont = 2
    response = None
    while cont != 0 and not response:
        response = requests.get(
            f"{URL}/consumers/my_json_consumer/instances/internal_consumer/records",
            headers=headers,
        ).json()
        cont -= 1

    return response


def close_consumer():
    headers = {"Content-Type": "application/vnd.kafka.json.v2+json"}
    requests.delete(
        f"{URL}/consumers/my_json_consumer/instances/internal_consumer", headers=headers
    )
