import requests
import json
import time
import uuid # For generating unique simulation IDs

# --- Configuration ---
# REPLACE THIS WITH YOUR API GATEWAY INVOKE URL from Phase 3, Step 4
API_GATEWAY_INVOKE_URL = "https://ho9xm652s7.execute-api.us-east-1.amazonaws.com/dev/simulations"
ECS_CLUSTER_NAME = "qiot-simulation-cluster"

# Simulation parameters for testing
TEST_NUM_DEVICES = 2 # Start with a small number
TEST_PUBLISH_FREQUENCY = 2 # seconds
TEST_DEVICE_TYPE = "temperature_humidity"

# --- Test Functions ---

def start_simulation(simulation_id, num_devices, frequency, device_type):
    print(f"\n--- Starting Simulation: {simulation_id} ---")
    payload = {
        "action": "start",
        "simulationId": simulation_id,
        "config": {
            "numDevices": num_devices,
            "frequency": frequency,
            "deviceType": device_type
        }
    }
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(API_GATEWAY_INVOKE_URL, data=json.dumps(payload), headers=headers)
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        result = response.json()
        print("Start Simulation API Response:")
        print(json.dumps(result, indent=2))
        return result
    except requests.exceptions.RequestException as e:
        print(f"Error starting simulation: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"API Error Response: {e.response.text}")
        return None

def stop_simulation(simulation_id):
    print(f"\n--- Stopping Simulation: {simulation_id} ---")
    payload = {
        "action": "stop",
        "simulationId": simulation_id
    }
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(API_GATEWAY_INVOKE_URL, data=json.dumps(payload), headers=headers)
        response.raise_for_status()
        result = response.json()
        print("Stop Simulation API Response:")
        print(json.dumps(result, indent=2))
        return result
    except requests.exceptions.RequestException as e:
        print(f"Error stopping simulation: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"API Error Response: {e.response.text}")
        return None

def get_simulation_status(simulation_id):
    print(f"\n--- Getting Status for Simulation: {simulation_id} ---")
    payload = {
        "action": "get_status",
        "simulationId": simulation_id
    }
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(API_GATEWAY_INVOKE_URL, data=json.dumps(payload), headers=headers)
        response.raise_for_status()
        result = response.json()
        print("Get Status API Response:")
        print(json.dumps(result, indent=2))
        return result
    except requests.exceptions.RequestException as e:
        print(f"Error getting simulation status: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"API Error Response: {e.response.text}")
        return None

def list_simulations():
    print("\n--- Listing All Simulations ---")
    payload = {
        "action": "list_simulations"
    }
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(API_GATEWAY_INVOKE_URL, data=json.dumps(payload), headers=headers)
        response.raise_for_status()
        result = response.json()
        print("List Simulations API Response:")
        print(json.dumps(result, indent=2))
        return result
    except requests.exceptions.RequestException as e:
        print(f"Error listing simulations: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"API Error Response: {e.response.text}")
        return None

# --- Main Test Execution ---
if __name__ == "__main__":
    if API_GATEWAY_INVOKE_URL == "YOUR_API_GATEWAY_INVOKE_URL":
        print("ERROR: Please replace 'YOUR_API_GATEWAY_INVOKE_URL' in the script with your actual API Gateway endpoint.")
        exit(1)

    unique_simulation_id = f"test-{uuid.uuid4().hex[:8]}" # Generate a unique ID

    # 1. Start a simulation
    start_result = start_simulation(unique_simulation_id, TEST_NUM_DEVICES, TEST_PUBLISH_FREQUENCY, TEST_DEVICE_TYPE)
    if start_result is None:
        print("\nTest failed at start simulation stage. Check Lambda logs for errors.")
        exit(1)

    print(f"\nSleeping for {TEST_PUBLISH_FREQUENCY * 5} seconds to allow Fargate tasks to launch and send data...")
    time.sleep(TEST_PUBLISH_FREQUENCY * 5) # Wait for some data to flow

    # 2. Get status of the started simulation
    get_status_result = get_simulation_status(unique_simulation_id)
    if get_status_result is None or get_status_result.get('status') != 'running':
        print("\nWarning: Simulation status not 'running' after initial wait. Check Fargate tasks in ECS.")

    # 3. List all simulations (to see if it appears)
    list_simulations_result = list_simulations()

    # --- Manual Verification Steps During Sleep ---
    print("\n--- MANUAL VERIFICATION STEPS ---")
    print(f"While the script is running (before stopping):")
    print(f"1. Check AWS ECS Console -> Clusters -> '{ECS_CLUSTER_NAME}' -> Tasks tab.")
    print(f"   You should see {TEST_NUM_DEVICES} running tasks for simulation '{unique_simulation_id}'.")
    print(f"2. Check AWS IoT Core Console -> Test client (MQTT test utility).")
    print(f"   Subscribe to topic 'iot/sensor/#'. You should see messages flowing.")
    print(f"3. Check Amazon Timestream Console -> Your database 'iot_sensor_data' -> Tables -> 'sensor_readings'.")
    print(f"   Run a query like 'SELECT * FROM \"iot_sensor_data\".\"sensor_readings\" WHERE simulationId = '{unique_simulation_id}''. You should see data.")
    print(f"4. Check AWS IoT TwinMaker Console -> Workspaces -> 'MyFargateIoTSpace' -> Entities tab.")
    print(f"   You should see new entities like 'DT_sensorDevice-{unique_simulation_id}-1', etc.")
    print(f"   Click on an entity and view its 'SensorDataComponent' properties to see real-time data.")
    print(f"5. Check Amazon Managed Grafana Console -> Your Dashboard.")
    print(f"   Try to update your dashboard's template variables (simulationId, sensorId) to match your test simulation.")
    print(f"   You should see graphs updating with data.")

    # 4. Keep the simulation running for a bit longer for manual checks
    print(f"\nKeeping simulation running for another {TEST_PUBLISH_FREQUENCY * 10} seconds for observation.")
    time.sleep(TEST_PUBLISH_FREQUENCY * 100)

    # 5. Stop the simulation
    stop_result = stop_simulation(unique_simulation_id)
    if stop_result is None:
        print("\nTest failed at stop simulation stage. Check Lambda logs for errors.")
        exit(1)

    print("\n--- Final Checks After Stopping ---")
    print("1. Check AWS ECS Console: The Fargate tasks for this simulation should now be stopped.")
    print("2. Check AWS IoT Core Console: The IoT Things and associated certificates should be deleted.")
    print("3. Check AWS IoT TwinMaker Console: The TwinMaker entities should be deleted.")
    print("4. Check DynamoDB: The entry for simulationId should show 'stopped' status.")

    print("\nBackend test script finished. Review logs and consoles for verification.")
