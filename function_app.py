import azure.functions as func
from azure.mgmt.sql import SqlManagementClient
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
from azure.mgmt.web import WebSiteManagementClient
import json
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
import winrm
import os
from time import sleep
import requests
import logging


app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
logging.basicConfig(filename="newfile.log",
                    format='%(asctime)s %(levelname)s: %(message)s',
                    level=logging.DEBUG)  # Set the logging level to DEBUG

def failover(resource_client,client, resource_group_name,locations,recovery_region,server_name,replica_server,web_client,compute_client,network_client,rec_res_group_name):
    server=client.servers.list_by_resource_group(resource_group_name)
    # logging.info(server)
    server_list=[]
    for i in server:
        server_list.append(i.name)
    if len(server_list) == 0:
        logging.info("404 : No Server found")
    def partner_server_rg(sql_server_name):
        for resource in resource_client.resources.list(filter=f"resourceType eq 'Microsoft.Sql/servers' and name eq '{sql_server_name}'"):
            server_resource_group = resource.id.split('/')[4]  # Extract resource group name from resource ID
            break
        return server_resource_group
    def make_fail_over(resource_group_name,server_name, database_name, recovery_region):
        primary=client.replication_links.list_by_database(resource_group_name, server_name, database_name)
        database_link_id = None
        for l in primary:
            # logging.info(l)
            database_link_id = l.name
            replica_server = l.partner_server
            # logging.info(l.partner_location.replace(" ", "").lower(), recovery_region)
            if l.partner_location.replace(" ", "").lower() == recovery_region.replace(" ", "").lower() and l.partner_role == "Secondary":
                replica_server_rg = partner_server_rg(replica_server)
                operation = client.replication_links.begin_failover(replica_server_rg, replica_server, database_name,database_link_id)
           
                logging.info("Primary - server : ",server_name,"-----   Seconday - server : ",replica_server)
                sleep(120)
                # Get all virtual machines in the resource group
                vms = compute_client.virtual_machines.list(rec_res_group_name)

                # Iterate over each virtual machine and get its public IP address
                for vm in vms:
                    # Get the network interface for the VM
                    nic_id = vm.network_profile.network_interfaces[0].id
                    nic_name = nic_id.split('/')[-1]
                    nic = network_client.network_interfaces.get(rec_res_group_name, nic_name)

                    # Get the public IP address for the network interface
                    if nic.ip_configurations[0].public_ip_address:
                        public_ip_id = nic.ip_configurations[0].public_ip_address.id
                        public_ip_name = public_ip_id.split('/')[-1]
                        public_ip_address = network_client.public_ip_addresses.get(rec_res_group_name, public_ip_name)
                        
                        import winrm

                        host = str(public_ip_address.ip_address)
                        user = os.environ["USER"]
                        password = os.environ["PASSWORD"]

                        try:
                            session = winrm.Session(host, auth=(user, password), transport='ntlm')
                            logging.info(session)
                            file_path = r'C:\Users\azure\Downloads\eShopOnWeb-main\eShopOnWeb-main\src\Web\appsettings.json'
        
                            cmd = f'if exist "{file_path}" (echo true) else (echo false)'
                            result = session.run_cmd(cmd)
                            logging.info(result)
        
                            if result.std_out.strip() == b'true':
                                old_db_name = server_name+'.database.windows.net'
                                new_db_name = replica_server+'.database.windows.net'
                                for i in range(5):
                                    sleep(20)
                                    cmd = f'Get-Content -Path "{file_path}"'
                                    result = session.run_ps(cmd)
                                    logging.info(result)
                                    file_contents = result.std_out.decode('utf-8')
            
                                    file_contents = file_contents.replace(old_db_name, new_db_name)
            
                                    cmd = f'Set-Content -Path "{file_path}" -Value @"\n{file_contents}\n"@'
                                    session.run_ps(cmd)
                                    logging.info(session)
        
                                logging.info('File Updated')
                                return func.HttpResponse(
                                    "200",
                                    status_code=200)
                            else:
                                logging.info('File does not exist or access denied')
                                return func.HttpResponse(f"Hello, {str(e)}. This HTTP triggered function executed successfully.", status_code=400)
                        except Exception as e:
                            logging.info(f'An error occurred: {str(e)}')
                            return func.HttpResponse(f"Hello, {str(e)}. This HTTP triggered function executed successfully.", status_code=400)
    for i in server_list:
        database_a=client.databases.list_by_server(resource_group_name,i)
        for j in database_a:
            if j.location==locations:
                if j.name != "master" and j.secondary_type == None:
                    make_fail_over(resource_group_name,i,j.name, recovery_region)

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
                logging.basicConfig(filename="newfile.log",
                    format='%(asctime)s %(message)s',
                    filemode='w')

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
        app_service_name = None
        for item in json2:
            if 'APP_SERVICE' in item:
                app_service_name = deployment_name+"-"+item['APP_SERVICE'][0]['name']
                break
        rec_res_group_name = None
        for item in json2:
            if 'RESOURCE_GROUP' in item:
                rec_res_group_name = deployment_name+"-"+item['RESOURCE_GROUP'][0]['name']
                break

        client_id = os.environ["CLIENT_ID"]
        client_secret = os.environ["CLIENT_SECRET"]
        tenant_id = os.environ["TENANT_ID"]
        # Create a client secret credential object
        credential = ClientSecretCredential(
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id
        )

        client = SqlManagementClient(credential, subscription_id)
        resource_client = ResourceManagementClient(credential, subscription_id)
        web_client = WebSiteManagementClient(credential, subscription_id)
        compute_client = ComputeManagementClient(credential, subscription_id)
        network_client = NetworkManagementClient(credential, subscription_id)

        server_name=None
        replica_server=None
        failover(resource_client ,client, resource_group_name, location, recovery_region,server_name,replica_server,web_client,compute_client,network_client,rec_res_group_name)
        
        
        return func.HttpResponse(
            "200",
            status_code=200)

    except Exception as e:
        logging.error(f"Error occurred: {str(e)}")
        return func.HttpResponse(f"Hello, {str(e)}. This HTTP triggered function executed successfully.", status_code=400)
