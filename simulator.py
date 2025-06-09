#simulator.py - simulates IoT Devices

import time
import json
import random
import os
import logging
import base64
from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTClient

# --- Configuration from Env Variables ---
IOT_CORE_ENDPOINT = os.environ.get('IOT_CORE_ENDPOINT')
THING_NAME = os.environ.get('THING_NAME')
PUBLISH_INTERVAL_SECONDS = int(os.environ.get('PUBLISH_INTERVAL_SECONDS', 5))
DEVICE_TYPE = os.environ.get('DEVICE_TYPE', 'temperature_humidity')
SIMULATION_ID = os.environ.get('SIMULATION_ID')

#Credentials are passed as env variables (Base64 encoded)
#This is for simplicity. For production, consider AWS Secrets Manager
ROOT_CA_PEM_B64 = os.environ.get('ROOT_CA_PEM')
CERTIFICATE_PEM_B64 = os.environ.get('CERTIFICATE_PEM')
PRIVATE_KEY_PEM_B64 = os.environ.get('PRIVATE_KEY_PEM')


if not all([IOT_CORE_ENDPOINT, THING_NAME, PUBLISH_INTERVAL_SECONDS, SIMULATION_ID ,ROOT_CA_PEM_B64, CERTIFICATE_PEM_B64, PRIVATE_KEY_PEM_B64]):
    missing_vars = [var for var in ["IOT_CORE_ENDPOINT", "THING_NAME", "PUBLISH_INTERVAL_SECONDS", "SIMULATION_ID", "ROOT_CA_PEM", "CERTIFICATE_PEM", "PRIVATE_KEY_PEM"] if not os.environ.get(var)]
    print(f"ERROR: Missing required environment varibales for IoT connection: {', '.join(missing_vars)}")
    exit(1)

#Decode base64 encoded credentials
try:
    ROOT_CA_PEM = base64.b64decode(ROOT_CA_PEM_B64).decode('utf-8') #Root CA might not be encoded as its common
    CERTIFICATE_PEM = base64.b64decode(CERTIFICATE_PEM_B64).decode('utf-8') #Ensure this is the actual PEM content, not base64 if decoded elsewhere
    PRIVATE_KEY_PEM = base64.b64decode(PRIVATE_KEY_PEM_B64).decode('utf-8') #Ensure this is the actual PEM content
except Exception as e:
    print(f"Error decoding credentials: {e}")
    exit(1)


# --- Create temporary files for credentials (required by AWSIoTPython SDK)
CERT_DIR = '/tmp/certs' #Fargate containers have writable /tmp
os.makedirs(CERT_DIR, exist_ok=True)

ROOT_CA_PATH = os.path.join(CERT_DIR, "root-CA.crt")
PRIVATE_KEY_PATH = os.path.join(CERT_DIR, "private.pem.key")
CERTIFICATE_PATH = os.path.join(CERT_DIR, "certifcate.pem.crt")

with open(ROOT_CA_PATH, 'w') as f: f.write(ROOT_CA_PEM)
with open(PRIVATE_KEY_PATH, 'w') as f: f.write(PRIVATE_KEY_PEM)
with open(CERTIFICATE_PATH, 'w') as f: f.write(CERTIFICATE_PEM)


#AWS IoT MQTT Client Setup
myMQTTClient = AWSIoTMQTTClient(THING_NAME)
myMQTTClient.configureEndpoint(IOT_CORE_ENDPOINT, 8883)
myMQTTClient.configureCredentials(ROOT_CA_PATH, PRIVATE_KEY_PATH, CERTIFICATE_PATH)

myMQTTClient.configureAutoReconnectBackoffTime(1,32,20)
myMQTTClient.configureOfflinePublishQueueing(-1) #infinite offline queuing
myMQTTClient.configureDrainingFrequency(2)
myMQTTClient.configureConnectDisconnectTimeout(10) #10 seconds
myMQTTClient.configureMQTTOperationTimeout(5) #5 seconds


try:
    print(f"Connecting {THING_NAME} to AWS IoT Core...")
    myMQTTClient.connect()
    print(f"{THING_NAME} connected.")
except Exception as e:
    print(f"Error connecting {THING_NAME} : {e}")
    exit(1)


# --- Sensor Simulation Loop ---
current_temp = random.uniform(20.0,30.0)
current_humidity = random.uniform(40.0, 60.0)
current_light = random.uniform(100, 1000)

while True:
    #Simulate sensor readings (slight variations)
    current_temp += random.uniform(-0.5, 0.5)
    current_humidity += random.uniform(-1.0, 1.0)
    current_light += random.uniform(-50, 50)

    #Keep values within a reasonable range
    current_temp = max(15.0, min(35.0, current_temp))
    current_humidity = max(30.0, min(70.0, current_humidity))
    current_light = max(50, min(1200, current_light))

    timestamp = int(time.time())

    payload = {
        "thing_name": THING_NAME,
        "temperature": round(current_temp, 2),
        "humidity": round(current_humidity, 2),
        "light": round(current_light, 2),
        "timestamp": timestamp,
        "status": "online",
        "last_updated": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    # create a topic for thing and shadow
    # Topic format: iot/sensor/SIMULATION_ID/THING_NAME/data
    topic = f"iot/sensor/{THING_NAME.split('-')[0]}-{THING_NAME.split('-')[1]}/{THING_NAME}/data"
    shadow_update_topic = f"$aws/things/{THING_NAME}/shadow/update"


    #publish data to both topics for device and shadow device
    try:
        myMQTTClient.publish(topic, json.dumps(payload), 1)
        print(f"{THING_NAME}: Published data to {topic}: {json.dumps(payload)}")
        myMQTTClient.publish(shadow_update_topic, json.dumps(payload), 1) #Update Device Shadow
        print(f"{THING_NAME}: Updated Device Shadow")
    except Exception as e:
        print(f"Error publishing from {THING_NAME}: {e}")

    time.sleep(PUBLISH_INTERVAL_SECONDS)