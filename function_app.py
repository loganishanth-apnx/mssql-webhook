import os
import logging
import requests
import azure.functions as func
from azure.identity import ClientSecretCredential
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
import winrm
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
logging.basicConfig(filename="newfile.log",
                    format='%(asctime)s %(levelname)s: %(message)s',
                    level=logging.DEBUG)  # Set the logging level to DEBUG

def get_partner_server_resource_group(client, sql_server_name):
    for resource in client.resources.list(filter=f"resourceType eq 'Microsoft.Sql/servers' and name eq '{sql_server_name}'"):
        server_resource_group = resource.id.split('/')[4]
        return server_resource_group

def promote_replica(client, resource_group_name, server_name, database_name, recovery_region):
    primary_links = client.replication_links.list_by_database(resource_group_name, server_name, database_name)
    
    for link in primary_links:
        database_link_id = link.name
        replica_server = link.partner_server
        if link.partner_location.replace(" ", "").lower() == recovery_region.replace(" ", "").lower() and link.partner_role == "Secondary":
            replica_server_rg = get_partner_server_resource_group(client, link.partner_server)
            operation = client.replication_links.begin_failover(replica_server_rg, link.partner_server, database_name, link.name)
            logging.info(f"Promoted replica for server {server_name} from  primary to Secondary {link.partner_server}")

def process_failover_request(credential, subscription_id,resource_group_name,primary_region,recovery_region,recovery_resource_group):

    client = SqlManagementClient(credential, subscription_id)
    resource_client = ResourceManagementClient(credential, subscription_id)
    server=client.servers.list_by_resource_group(resource_group_name)
    # logging.info(server)
    server_list=[]
    for i in server:
        server_list.append(server_iter.name)
    if len(server_list) == 0:
        logging.info("404 : No Server found")
    for server_iter in server_list:
        database_a=client.databases.list_by_server(resource_group_name,i)
        for database_iter in database_a:
            if database_iter.location==primary_region:
                if database_iter.name != "master" and database_iter.secondary_type == None:
                    promote_replica(resource_group_name,server_iter,database_iter.name, recovery_region)
    
@app.function_name(name="HttpTrigger")
@app.route(route="", auth_level=func.AuthLevel.ANONYMOUS)
def HttpTrigger(req: func.HttpRequest) -> func.HttpResponse:
    try:
        logging.info('Python HTTP trigger function processed a request.')
        request_json = req.get_json()
        logging.info(request_json)
        deployment_name = request_json['recoveryName']
        primary_resource_metadata_url = request_json['resourceMapping']['primaryResourceMetadataPath']
        recovered_metadata_url = request_json['resourceMapping']['recoveredMetadataPath']
        rec_id = request_json['recoveryId']
        # source_recovery_mapping_url = request_json['resourceMapping']['sourceRecoveryMappingPath']
        # Send GET requests and print the JSON responses
        json1 = requests.get(recovered_metadata_url).json()
        logging.info(json1)
        for item in json1:
            for key, value in item.items():
                for item_data in value:
                    recovery_resource_group = item_data['groupIdentifier']
                    recovery_region = item_data['region'].replace(
                        ' ', '').lower()
                    subscription_id = item_data['cloudResourceReferenceId'].split(
                        "/")[2]
                    break
        # Send GET requests and print the JSON responses
        json2 = requests.get(primary_resource_metadata_url).json()
        logging.info(json1)

        for item in json2:
            for key, value in item.items():
                for item_data in value:
                    resource_group_name = item_data['groupIdentifier']
                    location = item_data['region'].replace(' ', '').lower()
                    # recovery_subscription_id = item_data['cloudResourceReferenceId'].split("/")[2]
                    break
        client_id = os.environ["CLIENT_ID"]
        client_secret = os.environ["CLIENT_SECRET"]
        tenant_id = os.environ["TENANT_ID"]

        credential = ClientSecretCredential(
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id
        )

        process_failover_request(credential, subscription_id,resource_group_name,location,recovery_region,recovery_resource_group)
        return func.HttpResponse("200", status_code=200)

    except Exception as e:
        logging.error(f"Error occurred: {str(e)}")
        return func.HttpResponse(f"Error: {str(e)}", status_code=400)
