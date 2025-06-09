import json
import boto3
import os
import time
import base64
import traceback # Added for better error logging

dynamodb = boto3.client('dynamodb')
iot_client = boto3.client('iot')
ecs_client = boto3.client('ecs')
ssm_client = boto3.client('ssm')
iottwinmaker_client = boto3.client('iottwinmaker')


# --- Configuration from Lambda environment variables ---
SIM_CONFIG_TABLE = os.environ.get('SIM_CONFIG_TABLE')
THING_PREFIX = "sensorDevice" # Matches your simulator.py
IOT_POLICY_NAME = os.environ.get('IOT_POLICY_NAME') # Your IoT policy name
ECS_CLUSTER_NAME = os.environ.get('ECS_CLUSTER_NAME')
ECS_TASK_DEFINITION = os.environ.get('ECS_TASK_DEFINITION')
ECS_CONTAINER_NAME = os.environ.get('ECS_CONTAINER_NAME')
SUBNET_IDS = json.loads(os.environ.get('SUBNET_IDS')) if os.environ.get('SUBNET_IDS') else []
SECURITY_GROUP_IDS = json.loads(os.environ.get('SECURITY_GROUP_IDS')) if os.environ.get('SECURITY_GROUP_IDS') else []
IOT_CORE_ENDPOINT = os.environ.get('IOT_CORE_ENDPOINT')
ROOT_CA_SSM_PARAM = os.environ.get('ROOT_CA_SSM_PARAM') # /iot/root_ca_pem

# TwinMaker Workspace configuration
TWINMAKER_WORKSPACE_ID = os.environ.get('TWINMAKER_WORKSPACE_ID')
TWINMAKER_COMPONENT_TYPE_ID = os.environ.get('TWINMAKER_COMPONENT_TYPE_ID')


def get_root_ca_pem_content():
    """Retrieves Root CA content from SSM Parameter store"""
    try:
        response = ssm_client.get_parameter(Name=ROOT_CA_SSM_PARAM, WithDecryption=False)
        return response['Parameter']['Value']
    except ssm_client.exceptions.ParameterNotFound:
        print(f"Error: Root CA parameter '{ROOT_CA_SSM_PARAM}' not found.")
        raise
    except Exception as e:
        print(f"Error retrieving Root CA content from SSM: {e}")
        raise

def create_iot_thing_and_certs(thing_name, policy_name):
    """Creates IoT thing, its certificate, attaches policy and returns certificate details"""
    try:
        # Create Thing (idempotent, won't error if exists)
        try:
            iot_client.create_thing(thingName=thing_name)
            print(f"Created IoT Thing: '{thing_name}'")
        except iot_client.exceptions.ConflictException:
            print(f"IoT Thing '{thing_name}' already exists.")

        # Create Keys and Certificate (unique each time)
        cert_response = iot_client.create_keys_and_certificate(setAsActive=True)
        print(f"Created keys and certificates for '{thing_name}'.")

        certificate_pem = cert_response['certificatePem']
        private_key_pem = cert_response['keyPair']['PrivateKey'] # Corrected key
        certificate_arn = cert_response['certificateArn']
        certificate_id = cert_response['certificateId']

        # Attach Policy to Certificate
        iot_client.attach_policy(policyName=policy_name, target=certificate_arn)
        print(f"Attached policy '{policy_name}' to certificate '{certificate_id}'.")

        # Attach Certificate to Thing
        iot_client.attach_thing_principal(thingName=thing_name, principal=certificate_arn)
        print(f"Attached certificate '{certificate_id}' to thing '{thing_name}'.")

        return {
            "certificateArn": certificate_arn,
            "certificateId": certificate_id,
            "certificatePem": certificate_pem,
            "privateKeyPem": private_key_pem
        }
    except Exception as e:
        print(f"Error creating IoT thing/certs for '{thing_name}': {e}")
        raise

def delete_iot_thing_and_certs(thing_name, policy_name):
    """Deletes IoT thing, its certificate and detaches policy."""
    try:
        principals_response = iot_client.list_thing_principals(thingName=thing_name)
        if principals_response and principals_response['principals']:
            for principal_arn in principals_response['principals']: # Iterate through all principals
                if "cert/" in principal_arn: # Check if it's a certificate ARN
                    certificate_id = principal_arn.split('/')[-1]

                    # Detach policy from Certificate
                    try:
                        iot_client.detach_policy(policyName=policy_name, target=principal_arn)
                        print(f"Detached policy '{policy_name}' from certificate '{certificate_id}'.")
                    except iot_client.exceptions.ResourceNotFoundException:
                        print(f"Policy '{policy_name}' not attached to certificate '{certificate_id}' or not found. Skipping detach.")
                    except Exception as e:
                        print(f"Error detaching policy from certificate '{certificate_id}': {e}")

                    # Detach certificate from thing
                    try:
                        iot_client.detach_thing_principal(thingName=thing_name, principal=principal_arn)
                        print(f"Detached certificate '{certificate_id}' from thing '{thing_name}'.")
                    except iot_client.exceptions.ResourceNotFoundException:
                        print(f"Certificate '{certificate_id}' not attached to thing '{thing_name}' or not found. Skipping detach.")
                    except Exception as e:
                        print(f"Error detaching certificate from thing '{thing_name}': {e}")

                    # Update certificate status to INACTIVE and delete
                    try:
                        iot_client.update_certificate(certificateId=certificate_id, newStatus='INACTIVE')
                        print(f"Updated certificate '{certificate_id}' to INACTIVE.")
                        iot_client.delete_certificate(certificateId=certificate_id, forceDelete=True)
                        print(f"Certificate '{certificate_id}' deleted for '{thing_name}'.")
                    except iot_client.exceptions.CertificateStateException:
                         print(f"Certificate '{certificate_id}' already in INACTIVE state or being deleted.")
                    except iot_client.exceptions.ResourceNotFoundException:
                        print(f"Certificate '{certificate_id}' not found. Skipping deletion.")
                    except Exception as e:
                        print(f"Error deleting certificate '{certificate_id}': {e}")
                else:
                    print(f"Principal '{principal_arn}' is not a certificate, skipping deletion.")
        else:
            print(f"No certificate principals found for Thing '{thing_name}'. Skipping cert deletion.")

        # Delete thing
        try:
            iot_client.delete_thing(thingName=thing_name)
            print(f"Deleted IoT Thing '{thing_name}'.")
            return True
        except iot_client.exceptions.ResourceNotFoundException:
            print(f"Thing '{thing_name}' not found. Skipping deletion.")
            return False # Indicate it was already gone
        except Exception as e:
            print(f"Error deleting thing '{thing_name}': {e}")
            raise # Re-raise if thing deletion itself fails unexpectedly

    except iot_client.exceptions.ResourceNotFoundException as e:
        print(f"Resource not found when listing principals for '{thing_name}': {e}. Skipping deletion process.")
        return False # Indicate deletion attempts failed or resource didn't exist
    except Exception as e:
        print(f"Error in delete_iot_thing_and_certs for '{thing_name}': {e}")
        raise


def create_twinmaker_entity(thing_name, simulation_id):
    """Creates TwinMaker entity for the given thing_name and simulation_id"""
    entity_id = f"DT_{thing_name}" # Digital Twin Entity ID
    try:
        response = iottwinmaker_client.create_entity(
            workspaceId=TWINMAKER_WORKSPACE_ID,
            entityName=entity_id,
            description=f"Digital Twin for simulated IoT device '{thing_name}' in simulation '{simulation_id}'",
            components={
               'SensorDataComponent': { # Name of this component instance on the entity
                    'componentTypeId': TWINMAKER_COMPONENT_TYPE_ID, # Component type ID from TwinMaker workspace
                    'properties': {
                        'thingName': {
                            'value' : {
                                'stringValue': thing_name
                            }
                        }
                    }
                }
            }, # Closing brace for components dictionary (was missing in your original snippet)
            parentEntityId='$ROOT' # Create as root entity (corrected syntax)
        )
        print(f"Created TwinMaker entity '{entity_id}' for '{thing_name}'.")
        return response
    except iottwinmaker_client.exceptions.ConflictException:
        print(f"TwinMaker Entity '{entity_id}' already exists.")
        return None # Indicate that entity already exists
    except Exception as e:
        print(f"Error creating TwinMaker entity for '{thing_name}': {e}")
        raise


def delete_twinmaker_entity(thing_name): # Removed simulation_id as it's not used by this function
    """Deletes TwinMaker entity for the given thing_name"""
    entity_id = f"DT_{thing_name}" # Digital Twin Entity ID
    try:
        # Note: TwinMaker delete_entity might need isDeleted=True if it has children,
        # but typically for a leaf entity it's not strictly required unless you have specific sub-entities.
        # Adding it for robustness based on common patterns.
        response = iottwinmaker_client.delete_entity(
            workspaceId=TWINMAKER_WORKSPACE_ID,
            entityId=entity_id,
            isDeleted=True # Added for robustness, necessary if entities have child relationships
        )
        print(f"Deleted TwinMaker entity '{entity_id}' for '{thing_name}'.")
        return response
    except iottwinmaker_client.exceptions.ResourceNotFoundException:
        print(f"TwinMaker entity '{entity_id}' not found. Skipping deletion.")
        return None
    except Exception as e:
        print(f"Error deleting TwinMaker entity for '{thing_name}': {e}")
        raise


def lambda_handler(event, context):
    print(f"Received event: {json.dumps(event)}")
    action = event.get('action')
    simulation_id = event.get('simulationId') # For start/stop/get_status
    config = event.get('config', {}) # For 'start' action

    if action in ['start', 'stop', 'get_status'] and not simulation_id:
        return {
            'statusCode': 400,
            'body': json.dumps({'message': 'Missing simulationId for action. Simulation ID is required.'})
        }

    # Input validation for essential environment variables
    if not all([SIM_CONFIG_TABLE, ECS_CLUSTER_NAME, ECS_TASK_DEFINITION, ECS_CONTAINER_NAME,
                IOT_CORE_ENDPOINT, ROOT_CA_SSM_PARAM, TWINMAKER_WORKSPACE_ID, TWINMAKER_COMPONENT_TYPE_ID,
                SUBNET_IDS, SECURITY_GROUP_IDS]):
        missing_vars = [k for k, v in {
            'SIM_CONFIG_TABLE': SIM_CONFIG_TABLE,
            'ECS_CLUSTER_NAME': ECS_CLUSTER_NAME,
            'ECS_TASK_DEFINITION': ECS_TASK_DEFINITION,
            'ECS_CONTAINER_NAME': ECS_CONTAINER_NAME,
            'IOT_CORE_ENDPOINT': IOT_CORE_ENDPOINT,
            'ROOT_CA_SSM_PARAM': ROOT_CA_SSM_PARAM,
            'TWINMAKER_WORKSPACE_ID': TWINMAKER_WORKSPACE_ID,
            'TWINMAKER_COMPONENT_TYPE_ID': TWINMAKER_COMPONENT_TYPE_ID,
            'SUBNET_IDS': SUBNET_IDS,
            'SECURITY_GROUP_IDS': SECURITY_GROUP_IDS
        }.items() if not v]
        print(f"ERROR: Missing required environment variables: {', '.join(missing_vars)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'message': f"Lambda configuration error: Missing environment variables: {', '.join(missing_vars)}"})
        }


    try:
        if action == 'start':
            num_devices = int(config.get('numDevices', 1))
            frequency = int(config.get('frequency', 5))
            device_type = config.get('deviceType', 'temperature_humidity')

            # Store initial simulation config in DynamoDB with STARTING status
            dynamodb.put_item(
                TableName=SIM_CONFIG_TABLE,
                Item={
                    'simulationId': {'S': simulation_id},
                    'status': {'S': 'STARTING'},
                    'numDevices': {'N': str(num_devices)},
                    'frequency': {'N': str(frequency)},
                    'deviceType': {'S': device_type},
                    'startTime' : {'N': str(int(time.time()))},
                    'startedTasks': {'L': []} # Initialize as empty list of tasks
                }
            )

            root_ca_pem_content = get_root_ca_pem_content()

            started_tasks_data = [] # To accumulate info about successfully launched tasks

            for i in range(1, num_devices + 1):
                thing_name = f"{THING_PREFIX}-{simulation_id}-{i}"
                current_cert_id = None # Initialize for tracking current device's cert ID

                try:
                    # 1. Create IoT Thing & Certificates
                    response = iot_client.list_policies()
                    print("Available IoT policies:", [p['policyName'] for p in response['policies']])
                    certs_info = create_iot_thing_and_certs(thing_name, IOT_POLICY_NAME)
                    if not certs_info:
                        print(f"Skipping Fargate launch for {thing_name} due to failed cert creation.")
                        continue # Skip this device, try next one

                    current_cert_id = certs_info['certificateId']

                    # Encode PEM content to base64 for environment variables
                    cert_pem_b64 = base64.b64encode(certs_info['certificatePem'].encode('utf-8')).decode('utf-8')
                    private_key_b64 = base64.b64encode(certs_info['privateKeyPem'].encode('utf-8')).decode('utf-8')
                    root_ca_b64 = base64.b64encode(root_ca_pem_content.encode('utf-8')).decode('utf-8')

                    # 2. Launch Fargate Task for each simulator
                    run_task_params = {
                        'cluster': ECS_CLUSTER_NAME,
                        'launchType': 'FARGATE',
                        'taskDefinition': ECS_TASK_DEFINITION,
                        'count': 1,
                        'networkConfiguration': {
                            'awsvpcConfiguration': {
                                'subnets': SUBNET_IDS,
                                'securityGroups': SECURITY_GROUP_IDS,
                                'assignPublicIp': 'ENABLED' # Ensure Public IP for internet access (ECR, IoT Core)
                            }
                        },
                        'overrides': {
                            'containerOverrides': [
                                {
                                    'name': ECS_CONTAINER_NAME,
                                    'environment': [
                                        {'name': 'IOT_CORE_ENDPOINT', 'value': IOT_CORE_ENDPOINT},
                                        {'name': 'THING_NAME', 'value': thing_name},
                                        {'name': 'PUBLISH_INTERVAL_SECONDS', 'value': str(frequency)}, # Corrected env var name
                                        {'name': 'DEVICE_TYPE', 'value': device_type},
                                        {'name': 'SIMULATION_ID', 'value': simulation_id},
                                        {'name': 'ROOT_CA_PEM', 'value': root_ca_b64},
                                        {'name': 'CERTIFICATE_PEM', 'value': cert_pem_b64},
                                        {'name': 'PRIVATE_KEY_PEM', 'value': private_key_b64}
                                    ]
                                }
                            ]
                        },
                        'startedBy': f"simulation-controller-{simulation_id}", # For tracking
                        'enableExecuteCommand': True # Good for debugging running containers
                    }
                    # if ECS_TASK_ROLE_ARN: # Only add if the env var is set
                    #     run_task_params['taskRoleArn'] = ECS_TASK_ROLE_ARN
                    print("ECS task definition value:", run_task_params['taskDefinition'])
                    run_task_response = ecs_client.run_task(**run_task_params)

                    if run_task_response['tasks']:
                        task_arn = run_task_response['tasks'][0]['taskArn']
                        started_tasks_data.append({
                            'taskArn': task_arn,
                            'thingName': thing_name,
                            'certificateId': current_cert_id # Store cert ID for deletion
                        })
                        print(f"Started Fargate task '{task_arn}' for '{thing_name}'.")

                        # 3. Create TwinMaker Entity
                        create_twinmaker_entity(thing_name, simulation_id)

                    else:
                        print(f"Failed to launch Fargate task for '{thing_name}'. Response: {run_task_response.get('failures', 'No specific failures.')}")
                        # If Fargate task failed to launch, clean up the IoT resources for this specific device
                        print(f"Attempting to clean up IoT resources for '{thing_name}' due to Fargate launch failure.")
                        delete_iot_thing_and_certs(thing_name, IOT_POLICY_NAME)
                        # delete_twinmaker_entity(thing_name) # No twinmaker entity would have been created
                        continue # Skip this device, move to next

                except Exception as e:
                    print(f"An error occurred during setup for {thing_name}: {e}")
                    traceback.print_exc()
                    # Clean up if setup failed for this device
                    if current_cert_id: # Only attempt cleanup if a cert was actually created
                         print(f"Attempting to clean up IoT resources for '{thing_name}' due to setup error.")
                         delete_iot_thing_and_certs(thing_name, IOT_POLICY_NAME)
                    # No twinmaker entity would have been created if setup failed before it
                    continue # Try next device

            # Update DynamoDB with launched task ARNs and final status
            if started_tasks_data:
                dynamodb.update_item(
                    TableName=SIM_CONFIG_TABLE,
                    Key={'simulationId': {'S': simulation_id}},
                    UpdateExpression='SET startedTasks = :val, #s = :new_status',
                    ExpressionAttributeNames={'#s': 'status'}, # Define an alias for 'status'
                    ExpressionAttributeValues={
                        ':val': {"L": [{"M": {
                            "thingName": {"S": t['thingName']},
                            "taskArn": {"S": t['taskArn']},
                            "certificateId": {"S": t['certificateId']} # Keep cert ID here
                        }} for t in started_tasks_data]},
                        ':new_status': {'S': 'RUNNING'}
                    }
                )
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'message': 'Simulation started successfully, Fargate tasks and TwinMaker entities launched.',
                        'simulationId': simulation_id,
                        'startedTasks': started_tasks_data
                    })
                }
            else:
                # No tasks started successfully
                dynamodb.update_item(
                    TableName=SIM_CONFIG_TABLE,
                    Key={'simulationId': {'S': simulation_id}},
                    UpdateExpression='SET #s = :new_status',
                    ExpressionAttributeNames={'#s': 'status'},
                    ExpressionAttributeValues={':new_status': {'S': 'FAILED_TO_START'}}
                )
                return {
                    'statusCode': 500,
                    'body': json.dumps({'message': 'Simulation failed to start any Fargate tasks. Check logs for details.'})
                }

        elif action == 'stop':
            # Get tasks from DynamoDB for this simulation
            item_response = dynamodb.get_item(
                TableName=SIM_CONFIG_TABLE,
                Key={'simulationId': {'S': simulation_id}}
            )

            if "Item" not in item_response or 'startedTasks' not in item_response['Item']:
                return {
                    'statusCode': 404,
                    'body': json.dumps({'message': f'Simulation {simulation_id} not found or no tasks to stop.'})
                }

            tasks_to_process = item_response['Item']['startedTasks']['L']
            stopped_tasks_info = []

            for task_entry_dynamo in tasks_to_process:
                task_entry = task_entry_dynamo['M'] # Access the map
                task_arn = task_entry['taskArn']['S']
                thing_name = task_entry['thingName']['S']
                certificate_id_to_delete = task_entry.get('certificateId', {}).get('S') # Get cert ID if stored

                print(f"Attempting cleanup for thing: '{thing_name}', task: '{task_arn}'")

                try:
                    # 1. Stop Fargate task (idempotent, won't error if already stopped)
                    ecs_client.stop_task(
                        cluster=ECS_CLUSTER_NAME,
                        task=task_arn,
                        reason='Simulation stopped by user'
                    )
                    print(f"Requested stop for Fargate task '{task_arn}'.")
                except ecs_client.exceptions.ClusterNotFoundException:
                    print(f"ECS Cluster '{ECS_CLUSTER_NAME}' not found during stop for '{thing_name}'.")
                except ecs_client.exceptions.InvalidParameterException as e:
                    print(f"Task '{task_arn}' for '{thing_name}' already stopped or invalid: {e}")
                except Exception as e:
                    print(f"Error stopping task '{task_arn}' for '{thing_name}': {e}")

                try:
                    # 2. Delete TwinMaker entity
                    delete_twinmaker_entity(thing_name) # Removed simulation_id
                except Exception as e:
                    print(f"Error deleting TwinMaker entity for '{thing_name}': {e}")
                    traceback.print_exc()

                try:
                    # 3. Delete IoT Thing and certs
                    delete_iot_thing_and_certs(thing_name, IOT_POLICY_NAME) # Removed certificate_id
                except Exception as e:
                    print(f"Error deleting IoT thing/certs for '{thing_name}': {e}")
                    traceback.print_exc()

                stopped_tasks_info.append({
                    'taskArn': task_arn,
                    'thingName': thing_name
                })

            # Update DynamoDB simulation config status and end time
            dynamodb.update_item(
                TableName=SIM_CONFIG_TABLE,
                Key={'simulationId': {'S': simulation_id}},
                UpdateExpression='SET #s = :val, endTime = :et',
                ExpressionAttributeNames={'#s': 'status'}, # Define alias for 'status'
                ExpressionAttributeValues={
                    ':val': {'S': 'STOPPED'},
                    ':et': {'N': str(int(time.time()))}
                }
            )

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Simulation stopped. Fargate tasks and TwinMaker entities deleted.',
                    'simulationId': simulation_id,
                    'stoppedTasks': stopped_tasks_info
                })
            }

        elif action == 'get_status':
            item_response = dynamodb.get_item(
                TableName=SIM_CONFIG_TABLE,
                Key={'simulationId': {'S': simulation_id}}
            )
            if 'Item' in item_response:
                item = item_response['Item'] # Direct access to the item dictionary
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'simulationId': item.get('simulationId', {}).get('S'),
                        'status': item.get('status', {}).get('S'),
                        'numDevices': int(item.get('numDevices', {}).get('N', '0')),
                        'frequency': int(item.get('frequency', {}).get('N', '0')),
                        'deviceType': item.get('deviceType', {}).get('S'),
                        'startTime': int(item.get('startTime', {}).get('N', '0')),
                        'endTime': int(item.get('endTime', {}).get('N', '0')) if 'endTime' in item else None,
                        'startedTasks': [{"thingName": t['M']['thingName']['S'], "taskArn": t['M']['taskArn']['S']} for t in item.get('startedTasks', {}).get('L', [])] # Handle missing startedTasks gracefully
                    })
                }
            else:
                return {
                    'statusCode': 404,
                    'body': json.dumps({
                        'message': f'Simulation {simulation_id} not found',
                        'simulationId': simulation_id
                    })
                }

        elif action == 'list_simulations':
            response = dynamodb.scan(TableName=SIM_CONFIG_TABLE)
            simulations = []
            for item in response.get('Items', []):
                # Ensure all fields are handled gracefully if they don't exist in an item
                simulations.append({
                    'simulationId': item.get('simulationId', {}).get('S'),
                    'status': item.get('status', {}).get('S'),
                    'numDevices': int(item.get('numDevices', {}).get('N', '0')),
                    'frequency': int(item.get('frequency', {}).get('N', '0')),
                    'deviceType': item.get('deviceType', {}).get('S'),
                    'startTime': int(item.get('startTime', {}).get('N', '0')),
                    'endTime': int(item.get('endTime', {}).get('N', '0')) if 'endTime' in item else None,
                    'startedTasks': [{"thingName": t['M']['thingName']['S'], "taskArn": t['M']['taskArn']['S']} for t in item.get('startedTasks', {}).get('L', [])] # Handle missing startedTasks gracefully
                })
            return {
                'statusCode': 200,
                'body': json.dumps({'simulations': simulations})
            }

        else:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'message': 'Invalid action. Must be start, stop, get_status, or list_simulations',
                    'action': action
                })
            }
    except Exception as e:
        print(f"Error in lambda_handler: {e}")
        traceback.print_exc() # Print full traceback to CloudWatch
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Internal server error',
                'error': str(e),
                'traceback': traceback.format_exc() # Include traceback in response for debugging
            })
        }