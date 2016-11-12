from __future__ import print_function
import os
import json
import boto3
from botocore.client import Config

#=================================================
# Parameter constants
#=================================================
PARAMETER_ROOT = "ResourceProperties"
PARAMETER_ROOT_REQUEST_TYPE = "RequestType"
PARAMETER_NAMESPACE = "properties"
PARAMETER_PFX_PASSWORD = "pfx_password"
PARAMETER_BUCKET = "pfx_bucket"
PARAMETER_PFX_FILE = "pfx_file"
PARAMETER_CERTIFICATE_NAME = "certificate_name"

#=================================================
# Function constants
#=================================================
TMP_DIR = "/tmp/"
KEY_FILE = "downloaded_file.pfx"
LOCAL_KEY_FILE = TMP_DIR + KEY_FILE
KEY_PEM_FILE = TMP_DIR + "key.pem"
PRIVATE_KEY_FILE = TMP_DIR + "server_certificate.key"
SERVER_CERTIFICATE_FILE = TMP_DIR + "server_certificate.pem"

cfn_init = False
cfn_init_response_data = {}


#=================================================
# default handler
#=================================================
def lambda_handler(event, context):

    cfn_init = False

    # Validate the input parameters.
    if not parameters_are_valid(event):  return

    convert_certificate(event) 

    return "SUCCESS"


#=================================================
# function: convert_certificate
#=================================================
def convert_certificate(event):

    # Download the PFX file from S3.
    try:
      s3_client = boto3.client("s3", config=Config(signature_version='s3v4'))
      s3_client.download_file(event[PARAMETER_ROOT][PARAMETER_NAMESPACE][PARAMETER_BUCKET], event[PARAMETER_ROOT][PARAMETER_NAMESPACE][PARAMETER_PFX_FILE], LOCAL_KEY_FILE)

      pfx_password = event[PARAMETER_ROOT][PARAMETER_NAMESPACE][PARAMETER_PFX_PASSWORD]

      # Convert the PFX to a PEM-encoded file and then get generate certificate and private key files.
      os.system("openssl pkcs12 -in {0} -nocerts -out {1} -passout pass:{2} -passin pass:{2}".format(LOCAL_KEY_FILE, KEY_PEM_FILE, pfx_password))
      os.system("openssl pkcs12 -in {0} -clcerts -nokeys -out {1} -passin pass:{2}".format(LOCAL_KEY_FILE, SERVER_CERTIFICATE_FILE, pfx_password))
      os.system("openssl rsa -in {0} -out {1} -passin pass:{2}".format(KEY_PEM_FILE, PRIVATE_KEY_FILE, pfx_password))

      # Clear the password.
      pfx_password = ""
  
      # Upload the certificate to the IAM certificate store.
      response = boto3.client("iam").upload_server_certificate (
          ServerCertificateName = event[PARAMETER_ROOT][PARAMETER_NAMESPACE][PARAMETER_CERTIFICATE_NAME],
          CertificateBody = open(SERVER_CERTIFICATE_FILE, 'r').read(),
          PrivateKey = open(PRIVATE_KEY_FILE, 'r').read()
      )
      
      cfn_init_response_data["ServerCertificateName"] = response["ServerCertificateMetadata"]["ServerCertificateName"]
      cfn_init_response_data["Arn"] = response["ServerCertificateMetadata"]["Arn"]
        
    except Exception as e:
        print(e)
        if cfn_init:
            send_response_to_cloudformation(event, context, "FAILED", cfn_init_response_data)
        return "FAILURE: " + str(e)
    

#=================================================
# function: delete_certificate
# purpose:  deletes the certificate (normally if this function was invoked 
#           by CloudFormation and the stack is being rolled back)
#=================================================
def delete_certificate(event):

    try:
        # Delete the certificate to the IAM certificate store.
        response = boto3.client("iam").delete_server_certificate (
            ServerCertificateName = event[PARAMETER_ROOT][PARAMETER_NAMESPACE][PARAMETER_CERTIFICATE_NAME]
        )
        
    except Exception as e:
        print(e)
        if cfn_init:
            send_response_to_cloudformation(event, context, "FAILED", cfn_init_response_data)
        return "FAILURE: " + str(e)
    

#=================================================
# function: parameters_are_valid
# purpose:  validates the function parameters
#=================================================
def parameters_are_valid(event):
    
    parameter_errors = []
    parameters = []
    parameters.append(PARAMETER_PFX_PASSWORD)
    parameters.append(PARAMETER_BUCKET)
    parameters.append(PARAMETER_PFX_FILE)
    parameters.append(PARAMETER_CERTIFICATE_NAME)
    
    for parameter in parameters:
        if not parameter in event[PARAMETER_ROOT][PARAMETER_NAMESPACE]:
            parameter_errors.append(parameter)

    if parameter_errors:
        print("The following parameters were not provided: {}".format(parameter_errors))

    return not parameter_errors

#=================================================
# function: send_response_to_cloudformation
# purpose:  if this function was invoked by CloudFormation, then send 
#           a status response back to CloudFormation indicating the status
#=================================================
def send_response_to_cloudformation(event, context, response_status, response_data):
    
    response_body = {"Status": response_status,
                    "Reason": "See the details in CloudWatch logs: " + context.log_stream_name,
                    "PhysicalResourceId": context.log_stream_name,
                    "StackId": event["StackId"],
                    "RequestId": event["RequestId"],
                    "LogicalResourceId": event["LogicalResourceId"],
                    "Data": response_data}
                    
    
    try:
        request = requests.put(event["ResponseURL"], data=json.dumps(response_body))
        if request.status_code != 200:
            print (request.text)
            raise Exception("Encountered an error condition while sending request to CloudFormation.")
        return
    
    except requests.exceptions.RequestException as e:
        print (request.text)
        print (e)
        raise



