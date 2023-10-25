#/usr/bin/python3

import pandas as pd
from datetime import datetime
import math
import json
from os.path import expanduser
home = expanduser("~")

from argparse import ArgumentParser
parser = ArgumentParser()
parser.add_argument("-f", "--file", dest="filename",help="Source .csv file name that includes the logs that needs to be processed. Default value: ~/Downloads/events.csv", metavar="FILE", default=home+"/Downloads/events.csv")
args = parser.parse_args()

mapped_attr=[]
with open(home+"/Documents/Falcon-Crowdstrike-Events-Processor/config.json", "r") as config_file:
  config_content = json.load(config_file)
  mapped_attr=config_content["mapped_attributes"]

# Read the CSV file into a pandas DataFrame
df = pd.read_csv(args.filename)
#df.sort_values(by=['0'], ascending=False)

#config
processes_events=('ProcessRollup2','SyntheticProcessRollup2','ProcessBlocked','CommandHistory')
context_events=(
  'UserLogon','UserLogoff','UserLogonFailed','UserLogonFailed2',
  'HttpRequest',
  'NetworkConnectIP4','NetworkReceiveAcceptIP4','NetworkConnectIP6','NetworkReceiveAcceptIP6',
  'DnsRequest','SuspiciousDnsRequest'
  'JavaClassFileWritten','GzipFileWritten',
  'CriticalFileAccessed','CriticalEnvironmentVariableChanged',
  'ModuleBlockedEvent','ModuleBlockedEventWithPatternId','ScriptControlBlocked',
  'TerminateProcess','EndOfProcess',
  'CreateService','ServiceStarted','ModifyServiceBinary',
  'SuspiciousCreateSymbolicLink','SuspiciousRegAsepUpdate',
  'AsepValueUpdate',
  'DirectoryCreate','FileOpenInfo','RansomwareOpenFile',
  'ExecutableDeleted','NewExecutableRenamed','NewExecutableWritten','NewScriptWritten',
  'OleFileWritten','LnkFileWritten','JpegFileWritten','BmpFileWritten','CabFileWritten','PdfFileWritten','DmpFileWritten','ELFFileWritten','EmailFileWritten','EseFileWritten','GifFileWritten','JarFileWritten','LnkFileWritten','MsiFileWritten','ZipFileWritten','WebScriptFileWritten','TarFileWritten','PngFileWritten',
  'ProcessInjection','InjectedThread','BrowserInjectedThread'
)

# Since some event names like SyntheticProcessRollup2 and CommandHistory don't have parent process IDs, it's going to be problem because multiple unrelated processes will have a common process empty process ID.
# For this reason, it's important to separate these processes with a unique iterative inexistant ID
inexistant_process_id=-1

# Function to find all combinations of hexadecimal values
def find_hex_combinations(hex_str, hex_values):
    # Convert the input hexadecimal string to an integer
    input_value = int(hex_str, 16)
    # Create an empty list to store the combinations
    combinations = []
    # Iterate through the list of hexadecimal values
    for value in hex_values:
        # Check if the value is a valid combination
        if input_value & value['key'] == value['key']:
            # If it is, add it to the list of combinations
            combinations.append(value['value'])
    return combinations

json_graph={
  "edges": [],
  "nodes": []
}


json_tree={
  "name": "Independant Process Trees",
  "id": "Independant",
  "details": "",
  "context": [],
  "children": []
}

# Create a dictionary to store the process details
processes = {}
root_process_ids=[]
all_ids=[]
all_aid=[]
authentications={}
# Iterate over each row in the DataFrame
for index, row in df.iterrows():
  if row[mapped_attr["aid"]] not in all_aid:
    all_aid.append(row[mapped_attr["aid"]])
for index, row in df.iterrows():
  if row[mapped_attr["event_simpleName"]] in processes_events:
    if mapped_attr["TargetProcessId"] in row and row[mapped_attr["TargetProcessId"]]!='""' and row[mapped_attr["TargetProcessId"]]:
      if isinstance(row[mapped_attr["TargetProcessId"]],float):
        if math.isnan(row[mapped_attr["TargetProcessId"]]):
          process_id=''
        else:
          process_id = row[mapped_attr["TargetProcessId"]].replace('"','')
      else:
        process_id = row[mapped_attr["TargetProcessId"]].replace('"','')
    else:
      process_id=''

    if mapped_attr["ParentProcessId"] in row and row[mapped_attr["ParentProcessId"]]!='""' and row[mapped_attr["ParentProcessId"]]:
      if isinstance(row[mapped_attr["ParentProcessId"]],float):
        if math.isnan(row[mapped_attr["ParentProcessId"]]):
          parent_id=''
        else:
          parent_id = row[mapped_attr["ParentProcessId"]].replace('"','')
      else:
        parent_id = row[mapped_attr["ParentProcessId"]].replace('"','')
    else:
      parent_id=''

    command_line = row[mapped_attr["CommandLine"]]
    #sha256 = row[mapped_attr["SHA256HashData"]]

    if mapped_attr["SHA256HashData"] in row and row[mapped_attr["SHA256HashData"]]!='""' and row[mapped_attr["SHA256HashData"]]:
      if isinstance(row[mapped_attr["SHA256HashData"]],float):
        if math.isnan(row[mapped_attr["SHA256HashData"]]):
          sha256=''
        else:
          sha256=row[mapped_attr["SHA256HashData"]].replace('"','')
      else:
        sha256=row[mapped_attr["SHA256HashData"]].replace('"','')
    else:
      sha256=''

    if mapped_attr["SHA1HashData"] in row and row[mapped_attr["SHA1HashData"]]!='""' and row[mapped_attr["SHA1HashData"]]:
      if isinstance(row[mapped_attr["SHA1HashData"]],float):
        if math.isnan(row[mapped_attr["SHA1HashData"]]):
          sha1=''
        else:
          sha1=row[mapped_attr["SHA1HashData"]].replace('"','')
      else:
        sha1=row[mapped_attr["SHA1HashData"]].replace('"','')
    else:
      sha1=''

    if mapped_attr["MD5HashData"] in row and row[mapped_attr["MD5HashData"]]!='""' and row[mapped_attr["MD5HashData"]]:
      if isinstance(row[mapped_attr["MD5HashData"]],float):
        if math.isnan(row[mapped_attr["MD5HashData"]]):
          md5=''
        else:
          md5=row[mapped_attr["MD5HashData"]].replace('"','')
      else:
        md5=row[mapped_attr["MD5HashData"]].replace('"','')
    else:
      md5=''

    if mapped_attr["ProcessStartTime"] in row and row[mapped_attr["ProcessStartTime"]]!='""' and row[mapped_attr["ProcessStartTime"]]:
      if isinstance(row[mapped_attr["ProcessStartTime"]],float):
        if math.isnan(row[mapped_attr["ProcessEndTime"]]):
          dt_start = "0"
        else:
          dt_start = datetime.fromtimestamp(float(row[mapped_attr["ProcessStartTime"]]))
      else:
        dt_start = datetime.fromtimestamp(float(str(row[mapped_attr["ProcessStartTime"]]).replace('"','')))
    else:
      dt_start="0"

    if mapped_attr["ProcessEndTime"] in row and row[mapped_attr["ProcessEndTime"]]!='""' and row[mapped_attr["ProcessEndTime"]]:
      if isinstance(row[mapped_attr["ProcessEndTime"]],float):
        if math.isnan(row[mapped_attr["ProcessEndTime"]]):
          dt_end="0"
        else:
          dt_end = datetime.fromtimestamp(float(row[mapped_attr["ProcessEndTime"]]))
      else:
        dt_end = datetime.fromtimestamp(float(str(row[mapped_attr["ProcessEndTime"]]).replace('"','')))
    else:
      dt_end="0"

    if dt_start!="0" and dt_end!="0":
      #dt1 = datetime.fromtimestamp(dt_start)
      #dt2 = datetime.fromtimestamp(dt_end)
      #dt_duration = dt2 - dt1
      dt_duration= dt_end-dt_start
    else:
      dt_duration="undetermined"

    if mapped_attr["SourceProcessId"] in row and row[mapped_attr["SourceProcessId"]]!='""' and row[mapped_attr["SourceProcessId"]]:
      if isinstance(row[mapped_attr["SourceProcessId"]],float):
        if math.isnan(row[mapped_attr["SourceProcessId"]]):
          None
        else:
          if row[mapped_attr["SourceProcessId"]].replace('"','') not in all_ids:
            all_ids.append(row[mapped_attr["SourceProcessId"]].replace('"',''))
      else:
        if row[mapped_attr["SourceProcessId"]].replace('"','') not in all_ids:
          all_ids.append(row[mapped_attr["SourceProcessId"]].replace('"',''))
    else:
      None

    if mapped_attr["TargetProcessId"] in row and row[mapped_attr["TargetProcessId"]]!='""' and row[mapped_attr["TargetProcessId"]]:
      if isinstance(row[mapped_attr["TargetProcessId"]],float):
        if math.isnan(row[mapped_attr["TargetProcessId"]]):
          None
        else:
          if row[mapped_attr["TargetProcessId"]].replace('"','') not in all_ids:
            all_ids.append(row[mapped_attr["TargetProcessId"]].replace('"',''))
      else:
        if row[mapped_attr["TargetProcessId"]].replace('"','') not in all_ids:
          all_ids.append(row[mapped_attr["TargetProcessId"]].replace('"',''))
    else:
      None

    if mapped_attr["ParentProcessId"] in row and row[mapped_attr["ParentProcessId"]]!='""' and row[mapped_attr["ParentProcessId"]]:
      if isinstance(row[mapped_attr["ParentProcessId"]],float):
        if math.isnan(row[mapped_attr["ParentProcessId"]]):
          None
        else:
          if row[mapped_attr["ParentProcessId"]].replace('"','') not in all_ids:
            all_ids.append(row[mapped_attr["ParentProcessId"]].replace('"',''))
      else:
        if row[mapped_attr["ParentProcessId"]].replace('"','') not in all_ids:
          all_ids.append(row[mapped_attr["ParentProcessId"]].replace('"',''))
    else:
      None

    if mapped_attr["SourceThreadId"] in row and row[mapped_attr["SourceThreadId"]]!='""' and row[mapped_attr["SourceThreadId"]]:
      if isinstance(row[mapped_attr["SourceThreadId"]],float):
        if math.isnan(row[mapped_attr["SourceThreadId"]]):
          None
        else:
          if row[mapped_attr["SourceThreadId"]].replace('"','') not in all_ids:
            all_ids.append(row[mapped_attr["SourceThreadId"]].replace('"',''))
      else:
        if row[mapped_attr["SourceThreadId"]].replace('"','') not in all_ids:
          all_ids.append(row[mapped_attr["SourceThreadId"]].replace('"',''))
    else:
      None

    if mapped_attr["RpcClientProcessId"] in row and row[mapped_attr["RpcClientProcessId"]]!='""' and row[mapped_attr["RpcClientProcessId"]]:
      if isinstance(row[mapped_attr["RpcClientProcessId"]],float):
        if math.isnan(row[mapped_attr["RpcClientProcessId"]]):
          None
        else:
          if row[mapped_attr["RpcClientProcessId"]].replace('"','') not in all_ids:
            all_ids.append(row[mapped_attr["RpcClientProcessId"]].replace('"',''))
      else:
        if row[mapped_attr["RpcClientProcessId"]].replace('"','') not in all_ids:
          all_ids.append(row[mapped_attr["RpcClientProcessId"]].replace('"',''))
    else:
      None

    if mapped_attr["RpcClientThreadId"] in row and row[mapped_attr["RpcClientThreadId"]]!='""' and row[mapped_attr["RpcClientThreadId"]]:
      if isinstance(row[mapped_attr["RpcClientThreadId"]],float):
        if math.isnan(row[mapped_attr["RpcClientThreadId"]]):
          None
        else:
          if row[mapped_attr["RpcClientThreadId"]].replace('"','') not in all_ids:
            all_ids.append(row[mapped_attr["RpcClientThreadId"]].replace('"',''))
      else:
        if row[mapped_attr["RpcClientThreadId"]].replace('"','') not in all_ids:
          all_ids.append(row[mapped_attr["RpcClientThreadId"]].replace('"',''))
    else:
      None

    if mapped_attr["ImageFileName"] in row:
      if isinstance(row[mapped_attr["ImageFileName"]],float):
        image_file_name=''
      else:
        image_file_name = row[mapped_attr["ImageFileName"]].replace('"','')
    else:
      image_file_name=''

    if mapped_attr["ParentBaseFileName"] in row:
      if isinstance(row[mapped_attr["ParentBaseFileName"]],float):
        parent_base_file_name=''
      else:
        parent_base_file_name = row[mapped_attr["ParentBaseFileName"]].replace('"','')
    else:
      parent_base_file_name=''

    if mapped_attr["CommandHistory"] in row:
      if isinstance(row[mapped_attr["CommandHistory"]],float):
        command_history=''
      else:
        command_history = row[mapped_attr["CommandHistory"]].replace('"','')
    else:
      command_history=''

    if mapped_attr["AuthenticationId"] in row and row[mapped_attr["AuthenticationId"]]!='""' and row[mapped_attr["AuthenticationId"]]:
      if isinstance(row[mapped_attr["AuthenticationId"]],float):
        if math.isnan(row[mapped_attr["AuthenticationId"]]):
          authentication_id=''
        else:
          authentication_id=row[mapped_attr["AuthenticationId"]].replace('"','')
      else:
        authentication_id=row[mapped_attr["AuthenticationId"]].replace('"','')
    else:
      authentication_id=''
    if authentication_id=='0':
        authentication_id=authentication_id+" (Invalid LUID)"
    elif authentication_id=='996':
        authentication_id=authentication_id+" (Network Service)"
    elif authentication_id=='997':
        authentication_id=authentication_id+" (Local Service)"
    elif authentication_id=='999':
        authentication_id=authentication_id+" (System)"

    if mapped_attr["ParentAuthenticationId"] in row and row[mapped_attr["ParentAuthenticationId"]]!='""' and row[mapped_attr["ParentAuthenticationId"]]:
      if isinstance(row[mapped_attr["ParentAuthenticationId"]],float):
        if math.isnan(row[mapped_attr["ParentAuthenticationId"]]):
          parent_authentication_id=''
        else:
          parent_authentication_id=row[mapped_attr["ParentAuthenticationId"]].replace('"','')
      else:
        parent_authentication_id=row[mapped_attr["ParentAuthenticationId"]].replace('"','')
    else:
      parent_authentication_id=''
    if parent_authentication_id=='0':
        parent_authentication_id=parent_authentication_id+" (Invalid LUID)"
    elif parent_authentication_id=='996':
        parent_authentication_id=parent_authentication_id+" (Network Service)"
    elif parent_authentication_id=='997':
        parent_authentication_id=parent_authentication_id+" (Local Service)"
    elif parent_authentication_id=='999':
        parent_authentication_id=parent_authentication_id+" (System)"

    if mapped_attr["SessionId"] in row and row[mapped_attr["SessionId"]]!='""' and row[mapped_attr["SessionId"]]:
      if isinstance(row[mapped_attr["SessionId"]],float):
        if math.isnan(row[mapped_attr["SessionId"]]):
          session_id=''
        else:
          session_id=row[mapped_attr["SessionId"]].replace('"','')
      else:
        session_id=row[mapped_attr["SessionId"]].replace('"','')
    else:
      session_id=''

    if mapped_attr["UserSid"] in row:
      if isinstance(row[mapped_attr["UserSid"]],float):
        user_sid=''
      else:
        user_sid = row[mapped_attr["UserSid"]].replace('"','')
    else:
      user_sid=''
    if user_sid:
      user_sid=user_sid+' (read more: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)'

    if mapped_attr["TokenType"] in row:
      if isinstance(row[mapped_attr["TokenType"]],float):
        token_type=''
      else:
        token_type = row[mapped_attr["TokenType"]].replace('"','')
    else:
      token_type=''
    if token_type=='0':
        token_type="'Invalid Token'"
    elif token_type=='1':
        token_type="'Primary Token'"
    elif token_type=='2':
        token_type="'Impersonation Token'"


    # Create a new process dictionary if the processID doesn't exist
    if process_id not in processes:
        processes[process_id] = {'Children': []}

    # Update the process details
    if process_id and dt_start:
      processes[process_id]['AID'] = row[mapped_attr["aid"]]
      processes[process_id]['EVENT_SIMPLE_NAME'] = row[mapped_attr["event_simpleName"]]
      if row[mapped_attr["event_simpleName"]]=='CommandHistory':
        processes[process_id]['COMMAND_LINE'] = command_history
      else:
        processes[process_id]['COMMAND_LINE'] = command_line
      processes[process_id]['SHA256'] = sha256
      processes[process_id]['SHA1'] = sha1
      processes[process_id]['MD5'] = md5
      if parent_id!='':
        processes[process_id]['PARENT_PROCESS_ID'] = parent_id
      else:
        processes[process_id]['PARENT_PROCESS_ID'] = inexistant_process_id
        inexistant_process_id=inexistant_process_id-1
      processes[process_id]['PROCESS_START_TIME'] = dt_start
      processes[process_id]['PROCESS_END_TIME'] = dt_end
      processes[process_id]['PROCESS_DURATION_TIME'] = dt_duration
      processes[process_id]['AUTHENTICATION_ID']= authentication_id
      processes[process_id]['PARENT_AUTHENTICATION_ID']= parent_authentication_id
      processes[process_id]['SESSION_ID']= session_id
      processes[process_id]['USER_SID']= user_sid
      processes[process_id]['TOKEN_TYPE']= token_type
      processes[process_id]['IMAGE_FILE_NAME']= image_file_name
      processes[process_id]['PARENT_BASE_FILE_NAME']= parent_base_file_name
      processes[process_id]['Context'] = []
      #if '70074305948127'==process_id:
      #  print(processes[process_id])
      #  exit()

      # If a process has a parent and it's in the root_process_ids list
      if process_id in root_process_ids and parent_id:
        root_process_ids.remove(process_id)

      if process_id not in all_ids:
        all_ids.append(process_id)

      # If the parent process ID doesn't have a process object yet (maybe it will not have it at all)
      if parent_id not in processes:
        processes[parent_id]={}
        processes[parent_id]['AID'] = row[mapped_attr["aid"]]
        processes[parent_id]['EVENT_SIMPLE_NAME'] = 'PotentialProcessRollup2'
        processes[parent_id]['COMMAND_LINE'] = 'unknown'
        processes[parent_id]['SHA256'] = 'unknown'
        processes[parent_id]['SHA1'] = 'unknown'
        processes[parent_id]['MD5'] = 'unknown'
        processes[parent_id]['PARENT_PROCESS_ID'] = '0'
        processes[parent_id]['PROCESS_START_TIME'] = '0'
        processes[parent_id]['PROCESS_END_TIME'] = '0'
        processes[parent_id]['PROCESS_DURATION_TIME'] = 'undetermined'
        processes[parent_id]['AUTHENTICATION_ID'] = 'unknown'
        processes[parent_id]['PARENT_AUTHENTICATION_ID'] = 'unknown'
        processes[parent_id]['SESSION_ID'] = 'unknown'
        processes[parent_id]['USER_SID'] = 'unknown'
        processes[parent_id]['TOKEN_TYPE'] = 'unknown'
        processes[parent_id]['IMAGE_FILE_NAME'] = 'unknown'
        processes[parent_id]['Children'] = []
        processes[parent_id]['Context'] = []
        if parent_id not in root_process_ids:
          root_process_ids.append(parent_id)
      # Knowing the parent process without using this trick will not be possible
      if (processes[parent_id]['IMAGE_FILE_NAME']=='' or processes[parent_id]['IMAGE_FILE_NAME']=='unknown') and processes[process_id]['PARENT_BASE_FILE_NAME']!='':
        processes[parent_id]['IMAGE_FILE_NAME']=processes[process_id]['PARENT_BASE_FILE_NAME']
      if (processes[parent_id]['AUTHENTICATION_ID']=='' or processes[parent_id]['AUTHENTICATION_ID']=='unknown') and processes[process_id]['PARENT_AUTHENTICATION_ID']!='':
        processes[parent_id]['AUTHENTICATION_ID']=processes[process_id]['PARENT_AUTHENTICATION_ID']


for index, row in df.iterrows():
  if row[mapped_attr["event_simpleName"]] in context_events:
    if mapped_attr["ContextProcessId"] in row and row[mapped_attr["ContextProcessId"]]!='""' and row[mapped_attr["ContextProcessId"]]:
      if (isinstance(row[mapped_attr["ContextProcessId"]],float) or isinstance(row[mapped_attr["ContextProcessId"]],int)) and math.isnan(row[mapped_attr["ContextProcessId"]]):
        context_id=''
      else:
        context_id = row[mapped_attr["ContextProcessId"]].replace('"','')
    else:
      context_id=''
    if context_id=='':
      if mapped_attr["TargetProcessId"] in row and row[mapped_attr["TargetProcessId"]]!='""' and row[mapped_attr["TargetProcessId"]]:
        if (isinstance(row[mapped_attr["TargetProcessId"]],float) or isinstance(row[mapped_attr["TargetProcessId"]],int)) and math.isnan(row[mapped_attr["ContextProcessId"]]):
          context_id=''
        else:
          context_id = row[mapped_attr["TargetProcessId"]].replace('"','')
      else:
        context_id=''

    if mapped_attr["ContextThreadId"] in row and row[mapped_attr["ContextThreadId"]]!='""' and row[mapped_attr["ContextThreadId"]]:
      if (isinstance(row[mapped_attr["ContextThreadId"]],float) or isinstance(row[mapped_attr["ContextThreadId"]],int)) and math.isnan(row[mapped_attr["ContextThreadId"]]):
        context_thread_id=''
      else:
        context_thread_id = row[mapped_attr["ContextThreadId"]].replace('"','')
    else:
      context_thread_id=''

    if mapped_attr["RpcClientProcessId"] in row and row[mapped_attr["RpcClientProcessId"]]!='""' and row[mapped_attr["RpcClientProcessId"]]:
      if (isinstance(row[mapped_attr["RpcClientProcessId"]],float) or isinstance(row[mapped_attr["RpcClientProcessId"]],int)) and math.isnan(row[mapped_attr["RpcClientProcessId"]]):
        rpc_client_process_id=''
      else:
        rpc_client_process_id = row[mapped_attr["RpcClientProcessId"]].replace('"','')
    else:
      rpc_client_process_id=''

    if mapped_attr["ContextTimeStamp"] in row and row[mapped_attr["ContextTimeStamp"]]!='""' and row[mapped_attr["ContextTimeStamp"]]:
      if isinstance(row[mapped_attr["ContextTimeStamp"]],float):
        if math.isnan(row[mapped_attr["ContextTimeStamp"]]):
          dt_instant = "0"
        else:
          dt_instant = datetime.fromtimestamp(float(row[mapped_attr["ContextTimeStamp"]]))
      else:
        dt_instant = datetime.fromtimestamp(float(str(row[mapped_attr["ContextTimeStamp"]]).replace('"','')))
    else:
      dt_instant="0"

    if mapped_attr["TargetProcessId"] in row and row[mapped_attr["TargetProcessId"]]!='""' and row[mapped_attr["TargetProcessId"]]:
      if isinstance(row[mapped_attr["TargetProcessId"]],float):
        if math.isnan(row[mapped_attr["TargetProcessId"]]):
          target_process_id=''
        else:
          target_process_id = row[mapped_attr["TargetProcessId"]].replace('"','')
      else:
        target_process_id = row[mapped_attr["TargetProcessId"]].replace('"','')
    else:
      target_process_id=''

    if mapped_attr["TargetThreadId"] in row and row[mapped_attr["TargetThreadId"]]!='""' and row[mapped_attr["TargetThreadId"]]:
      if isinstance(row[mapped_attr["TargetThreadId"]],float):
        if math.isnan(row[mapped_attr["TargetThreadId"]]):
          target_thread_id=''
        else:
          target_thread_id = row[mapped_attr["TargetThreadId"]].replace('"','')
      else:
        target_thread_id = row[mapped_attr["TargetThreadId"]].replace('"','')
    else:
      target_thread_id=''

    if mapped_attr["TargetFileName"] in row:
      if isinstance(row[mapped_attr["TargetFileName"]],float):
        target_file_name=''
      else:
        target_file_name = row[mapped_attr["TargetFileName"]].replace('"','')
    else:
      target_file_name=''

    if mapped_attr["Size"] in row:
      if isinstance(row[mapped_attr["Size"]],float):
        size=''
      else:
        size = row[mapped_attr["Size"]].replace('"','')
    else:
      size=''

    if mapped_attr["IsOnRemovableDisk"] in row:
      if isinstance(row[mapped_attr["IsOnRemovableDisk"]],float):
        is_on_removable_disk=''
      else:
        is_on_removable_disk = row[mapped_attr["IsOnRemovableDisk"]].replace('"','')
    else:
      is_on_removable_disk=''

    if mapped_attr["IsOnNetwork"] in row:
      if isinstance(row[mapped_attr["IsOnNetwork"]],float):
        is_on_network=''
      else:
        is_on_network = row[mapped_attr["IsOnNetwork"]].replace('"','')
    else:
      is_on_network=''

    if mapped_attr["TargetProcessId"] in row and row[mapped_attr["TargetProcessId"]]!='""' and row[mapped_attr["TargetProcessId"]]:
      if isinstance(row[mapped_attr["TargetProcessId"]],int):
        if math.isnan(row[mapped_attr["TargetProcessId"]]):
          None
        else:
          if row[mapped_attr["TargetProcessId"]].replace('"','') not in all_ids:
            all_ids.append(row[mapped_attr["TargetProcessId"]].replace('"',''))

    if mapped_attr["ImageFileName"] in row:
      if isinstance(row[mapped_attr["ImageFileName"]],float):
        image_file_name=''
      else:
        image_file_name = row[mapped_attr["ImageFileName"]].replace('"','')
    else:
      image_file_name=''

    if mapped_attr["AuthenticationId"] in row and row[mapped_attr["AuthenticationId"]]!='""' and row[mapped_attr["AuthenticationId"]]:
      if isinstance(row[mapped_attr["AuthenticationId"]],float):
        if math.isnan(row[mapped_attr["AuthenticationId"]]):
          authentication_id=''
        else:
          authentication_id=row[mapped_attr["AuthenticationId"]].replace('"','')
      else:
        authentication_id=row[mapped_attr["AuthenticationId"]].replace('"','')
    else:
      authentication_id=''
    if authentication_id=='0':
        authentication_id=authentication_id+" (Invalid LUID)"
    elif authentication_id=='996':
        authentication_id=authentication_id+" (Network Service)"
    elif authentication_id=='997':
        authentication_id=authentication_id+" (Local Service)"
    elif authentication_id=='999':
        authentication_id=authentication_id+" (System)"

    if mapped_attr["SessionId"] in row and row[mapped_attr["SessionId"]]!='""' and row[mapped_attr["SessionId"]]:
      if isinstance(row[mapped_attr["SessionId"]],float):
        if math.isnan(row[mapped_attr["SessionId"]]):
          session_id=''
        else:
          session_id=row[mapped_attr["SessionId"]].replace('"','')
      else:
        session_id=row[mapped_attr["SessionId"]].replace('"','')
    else:
      session_id=''

    if mapped_attr["LocalAddressIP4"] in row:
      if isinstance(row[mapped_attr["LocalAddressIP4"]],float):
        local_address_ip4=''
      else:
        local_address_ip4 = row[mapped_attr["LocalAddressIP4"]].replace('"','')
    else:
      local_address_ip4=''

    if mapped_attr["LocalAddressIP6"] in row:
      if isinstance(row[mapped_attr["LocalAddressIP6"]],float):
        local_address_ip6=''
      else:
        local_address_ip6 = row[mapped_attr["LocalAddressIP6"]].replace('"','')
    else:
      local_address_ip6=''

    if mapped_attr["LocalPort"] in row:
      if isinstance(row[mapped_attr["LocalPort"]],float):
        local_port=''
      else:
        local_port = row[mapped_attr["LocalPort"]].replace('"','')
    else:
      local_port=''

    if mapped_attr["Protocol"] in row:
      if isinstance(row[mapped_attr["Protocol"]],float):
        protocol=''
      else:
        protocol = row[mapped_attr["Protocol"]].replace('"','')
    else:
      protocol=''
    if protocol:
      if protocol=='0':
        protocol='IP'
      elif protocol=='1':
        protocol='ICMP'
      elif protocol=='6':
        protocol='TCP'
      elif protocol=='17':
        protocol='UDP'
      elif protocol=='41':
        protocol='IPv6'
      elif protocol=='58':
        protocol='ICMPv6'
      elif protocol=='255':
        protocol='UNKNOWN'

    if mapped_attr["RemoteAddressIP4"] in row:
      if isinstance(row[mapped_attr["RemoteAddressIP4"]],float):
        remote_address_ip4=''
      else:
        remote_address_ip4 = row[mapped_attr["RemoteAddressIP4"]].replace('"','')
    else:
      remote_address_ip4=''

    if mapped_attr["RemoteAddressIP6"] in row:
      if isinstance(row[mapped_attr["RemoteAddressIP6"]],float):
        remote_address_ip6=''
      else:
        remote_address_ip6 = row[mapped_attr["RemoteAddressIP6"]].replace('"','')
    else:
      remote_address_ip6=''

    if mapped_attr["RemotePort"] in row:
      if isinstance(row[mapped_attr["RemotePort"]],float):
        remote_port=''
      else:
        remote_port = row[mapped_attr["RemotePort"]].replace('"','')
    else:
      remote_port=''

    if mapped_attr["DomainName"] in row:
      if isinstance(row[mapped_attr["DomainName"]],float):
        domain_name=''
      else:
        domain_name = row[mapped_attr["DomainName"]].replace('"','')
    else:
      domain_name=''

    if mapped_attr["CNAMERecords"] in row:
      if isinstance(row[mapped_attr["CNAMERecords"]],float):
        cname_records=''
      else:
        cname_records = row[mapped_attr["CNAMERecords"]].replace('"','')
    else:
      cname_records=''

    if mapped_attr["RequestType"] in row:
      if isinstance(row[mapped_attr["RequestType"]],float):
        request_type=''
      else:
        request_type = row[mapped_attr["RequestType"]].replace('"','')
    else:
      request_type=''
    if request_type:
      request_type=hex(int(request_type))
      if request_type=='0x0000':
        request_type="'UNKNOWN'"
      elif request_type=='0x1':
        request_type="'A'"
      elif request_type=='0x2':
        request_type="'NS'"
      elif request_type=='0x5':
        request_type="'CNAME'"
      elif request_type=='0xc':
        request_type="'PTR'"
      elif request_type=='0xf':
        request_type="'MX'"
      elif request_type=='0x10':
        request_type="'TXT'"
      elif request_type=='0x1c':
        request_type="'AAAA'"
      elif request_type=='0x41':
        request_type="'HTTPS'"
      elif request_type=='0xff':
        request_type="'ANY'"

    if mapped_attr["IP4Records"] in row:
      if isinstance(row[mapped_attr["IP4Records"]],float):
        ip4_records=''
      else:
        ip4_records = row[mapped_attr["IP4Records"]].replace('"','')
    else:
      ip4_records=''

    if mapped_attr["IP6Records"] in row:
      if isinstance(row[mapped_attr["IP6Records"]],float):
        ip6_records=''
      else:
        ip6_records = row[mapped_attr["IP6Records"]].replace('"','')
    else:
      ip6_records=''

    if mapped_attr["QueryStatus"] in row:
      if isinstance(row[mapped_attr["QueryStatus"]],float):
        query_status=''
      else:
        query_status = row[mapped_attr["QueryStatus"]].replace('"','')
    else:
      query_status=''
    if query_status:
      if query_status=='0':
        query_status='OK'
      elif query_status=='9701':
        query_status='DNS_ERROR_RCODE_NAME_ERROR (9003)'
      elif query_status=='9003':
        query_status='DNS_ERROR_RCODE_NAME_ERROR (9003)'

    if mapped_attr["ServiceDisplayName"] in row:
      if isinstance(row[mapped_attr["ServiceDisplayName"]],float):
        service_display_name=''
      else:
        service_display_name = "'"+row[mapped_attr["ServiceDisplayName"]].replace('"','')+"'"
    else:
      service_display_name=''

    if mapped_attr["ServiceDescription"] in row:
      if isinstance(row[mapped_attr["ServiceDescription"]],float):
        service_description=''
      else:
        service_description = row[mapped_attr["ServiceDescription"]].replace('"','')
    else:
      service_description=''

    if mapped_attr["ServiceObjectName"] in row:
      if isinstance(row[mapped_attr["ServiceObjectName"]],float):
        service_object_name=''
      else:
        service_object_name = row[mapped_attr["ServiceObjectName"]].replace('"','')
    else:
      service_object_name=''

    if mapped_attr["ServiceErrorControl"] in row:
      if isinstance(row[mapped_attr["ServiceErrorControl"]],float):
        service_error_control=''
      else:
        service_error_control = row[mapped_attr["ServiceErrorControl"]].replace('"','')
    else:
      service_error_control=''
    if service_error_control=='0':
        service_error_control="'Error ignore'"
    elif service_error_control=='1':
        service_error_control="'Error normal'"
    elif service_error_control=='2':
        service_error_control="'Error severe'"
    elif service_error_control=='3':
        service_error_control="'Error critical'"

    if mapped_attr["ServiceImagePath"] in row:
      if isinstance(row[mapped_attr["ServiceImagePath"]],float):
        service_image_path=''
      else:
        service_image_path = row[mapped_attr["ServiceImagePath"]].replace('"','')
    else:
      service_image_path=''

    if mapped_attr["ServiceStart"] in row:
      if isinstance(row[mapped_attr["ServiceStart"]],float):
        service_start=''
      else:
        service_start = row[mapped_attr["ServiceStart"]].replace('"','')
        if service_start=="0":
            service_start="'Boot start'"
        if service_start=="1":
            service_start="'System start'"
        if service_start=="2":
            service_start="'Auto start'"
        if service_start=="3":
            service_start="'Demand start'"
        if service_start=="4":
            service_start="'Disabled'"
    else:
      service_start=''

    if mapped_attr["ServiceType"] in row:
      if isinstance(row[mapped_attr["ServiceType"]],float):
        service_type=''
      else:
        service_type = row[mapped_attr["ServiceType"]].replace('"','')
    else:
      service_type=''
    if service_type=='1':
        service_type="'Service Kernel Driver'"
    elif service_type=='2':
        service_type="'Service File System Driver'"
    elif service_type=='4':
        service_type="'Service Adapter'"
    elif service_type=='16':
        service_type="'Service Win32 Own Process'"
    elif service_type=='32':
        service_type="'Service Win32 Share Process'"
    elif service_type=='256':
        service_type="'Service Interactive Process'"

    if mapped_attr["TokenType"] in row:
      if isinstance(row[mapped_attr["TokenType"]],float):
        token_type=''
      else:
        token_type = row[mapped_attr["TokenType"]].replace('"','')
    else:
      token_type=''
    if token_type=='0':
        token_type="'Invalid Token'"
    elif token_type=='1':
        token_type="'Primary Token'"
    elif token_type=='2':
        token_type="'Impersonation Token'"

    if mapped_attr["HttpMethod"] in row:
      if isinstance(row[mapped_attr["HttpMethod"]],float):
        http_method=''
      else:
        http_method = row[mapped_attr["HttpMethod"]].replace('"','')
    else:
      http_method=''

    if mapped_attr["HttpHost"] in row:
      if isinstance(row[mapped_attr["HttpHost"]],float):
        http_host=''
      else:
        http_host = row[mapped_attr["HttpHost"]].replace('"','')
    else:
      http_host=''

    if mapped_attr["HttpPath"] in row:
      if isinstance(row[mapped_attr["HttpPath"]],float):
        http_path=''
      else:
        http_path = row[mapped_attr["HttpPath"]].replace('"','')
    else:
      http_path=''

    if mapped_attr["EnvironmentVariableName"] in row:
      if isinstance(row[mapped_attr["EnvironmentVariableName"]],float):
        environment_variable_name=''
      else:
        environment_variable_name = row[mapped_attr["EnvironmentVariableName"]].replace('"','')
    else:
      environment_variable_name=''

    if mapped_attr["EnvironmentVariableValue"] in row:
      if isinstance(row[mapped_attr["EnvironmentVariableValue"]],float):
        environment_variable_value=''
      else:
        environment_variable_value = row[mapped_attr["EnvironmentVariableValue"]].replace('"','')
    else:
      environment_variable_value=''

    if mapped_attr["LogonTime"] in row and row[mapped_attr["LogonTime"]]!='""' and row[mapped_attr["LogonTime"]]:
      if isinstance(row[mapped_attr["LogonTime"]],float):
        if math.isnan(row[mapped_attr["LogonTime"]]):
          logon_time = "0"
        else:
          logon_time = datetime.fromtimestamp(float(row[mapped_attr["LogonTime"]]))
      else:
        logon_time = datetime.fromtimestamp(float(str(row[mapped_attr["LogonTime"]]).replace('"','')))
    else:
      logon_time="0"

    if mapped_attr["SourceFileName"] in row:
      if isinstance(row[mapped_attr["SourceFileName"]],float):
        source_file_name=''
      else:
        source_file_name = row[mapped_attr["SourceFileName"]].replace('"','')
    else:
      source_file_name=''

    if mapped_attr["LogoffTime"] in row and row[mapped_attr["LogoffTime"]]!='""' and row[mapped_attr["LogoffTime"]]:
      if isinstance(row[mapped_attr["LogoffTime"]],float):
        if math.isnan(row[mapped_attr["LogoffTime"]]):
          logoff_time = "0"
        else:
          logoff_time = datetime.fromtimestamp(float(row[mapped_attr["LogoffTime"]]))
      else:
        logoff_time = datetime.fromtimestamp(float(str(row[mapped_attr["LogoffTime"]]).replace('"','')))
    else:
      logoff_time="0"

    if mapped_attr["LogonType"] in row:
      if isinstance(row[mapped_attr["LogonType"]],float):
        logon_type=''
      else:
        logon_type = row[mapped_attr["LogonType"]].replace('"','')
    else:
      logon_type=''
    if logon_type=='2':
        logon_type="'Interactive'"
    elif logon_type=='3':
        logon_type="'Network'"
    elif logon_type=='4':
        logon_type="'Batch'"
    elif logon_type=='5':
        logon_type="'Service'"
    elif logon_type=='6':
        logon_type="'Proxy'"
    elif logon_type=='7':
        logon_type="'Unlock'"
    elif logon_type=='8':
        logon_type="'Network cleartext'"
    elif logon_type=='9':
        logon_type="'New credentials'"
    elif logon_type=='10':
        logon_type="'Remote interactive'"
    elif logon_type=='11':
        logon_type="'Cached interactive'"
    elif logon_type=='12':
        logon_type="'Cached remote interactive'"
    elif logon_type=='13':
        logon_type="'Cached unlock'"

    if mapped_attr["PasswordLastSet"] in row and row[mapped_attr["PasswordLastSet"]]!='""' and row[mapped_attr["PasswordLastSet"]]:
      if isinstance(row[mapped_attr["PasswordLastSet"]],float):
        if math.isnan(row[mapped_attr["PasswordLastSet"]]):
          password_last_set = "0"
        else:
          password_last_set = datetime.fromtimestamp(float(row[mapped_attr["PasswordLastSet"]]))
      else:
        password_last_set = datetime.fromtimestamp(float(str(row[mapped_attr["PasswordLastSet"]]).replace('"','')))
    else:
      password_last_set="0"

    if mapped_attr["UserIsAdmin"] in row:
      if isinstance(row[mapped_attr["UserIsAdmin"]],float):
        user_is_admin=''
      else:
        user_is_admin = row[mapped_attr["UserIsAdmin"]].replace('"','')
    else:
      user_is_admin=''

    if mapped_attr["RemoteAccount"] in row:
      if isinstance(row[mapped_attr["RemoteAccount"]],float):
        remote_account=''
      else:
        remote_account = row[mapped_attr["RemoteAccount"]].replace('"','')
    else:
      remote_account=''

    if mapped_attr["UserName"] in row:
      if isinstance(row[mapped_attr["UserName"]],float):
        username=''
      else:
        username = row[mapped_attr["UserName"]].replace('"','')
    else:
      username=''

    if mapped_attr["ClientComputerName"] in row:
      if isinstance(row[mapped_attr["ClientComputerName"]],float):
        client_computer_name=''
      else:
        client_computer_name = row[mapped_attr["ClientComputerName"]].replace('"','')
    else:
      client_computer_name=''

    if mapped_attr["LogonDomain"] in row:
      if isinstance(row[mapped_attr["LogonDomain"]],float):
        logon_domain=''
      else:
        logon_domain = row[mapped_attr["LogonDomain"]].replace('"','')
    else:
      logon_domain=''

    if mapped_attr["LogonServer"] in row:
      if isinstance(row[mapped_attr["LogonServer"]],float):
        logon_server=''
      else:
        logon_server = row[mapped_attr["LogonServer"]].replace('"','')
    else:
      logon_server=''

    if mapped_attr["UserLogonFlags"] in row:
      if isinstance(row[mapped_attr["UserLogonFlags"]],float):
        logon_flags=''
      else:
        logon_flags = row[mapped_attr["UserLogonFlags"]].replace('"','')
    else:
      logon_flags=''
    if logon_flags:
      logon_flags=int(logon_flags)
      if logon_flags==0:
        logon_flags="'None'"
      elif logon_flags==1:
        logon_flags="'User is synthetic'"
      elif logon_flags==2:
        logon_flags="'User is admin'"
      elif logon_flags==3:
        logon_flags="'User is synthetic and admin'"
      elif logon_flags==4:
        logon_flags="'User is local'"
      elif logon_flags==5:
        logon_flags="'User is synthetic and local'"
      elif logon_flags==6:
        logon_flags="'User is local and admin'"
      elif logon_flags==7:
        logon_flags="'User is synthetic, local and admin'"
      elif logon_flags==8:
        logon_flags="'User is built-in'"
      elif logon_flags==9:
        logon_flags="'User is built-in and synthetic'"
      elif logon_flags==10:
        logon_flags="'User is built-in and admin'"
      elif logon_flags==11:
        logon_flags="'User is built-in, synthetic and admin'"
      elif logon_flags==12:
        logon_flags="'User is built-in and local'"
      elif logon_flags==13:
        logon_flags="'User is built-in, synthetic and local'"
      elif logon_flags==14:
        logon_flags="'User is built-in, local and admin'"
      elif logon_flags==15:
        logon_flags="'User is built-in, synthetic, local and admin'"
      elif logon_flags==16:
        logon_flags="'User identity missing'"

    if mapped_attr["SubStatus"] in row:
      if isinstance(row[mapped_attr["SubStatus"]],float):
        substatus=''
      else:
        substatus = row[mapped_attr["SubStatus"]].replace('"','')
    else:
      substatus=''
    if substatus:
      substatus=hex(int(substatus))
      if substatus=='0xc0000064':
        substatus="'User name does not exist'"
      elif substatus=='0xc000006a':
        substatus="'User name is correct but the password is wrong'"
      elif substatus=='0xc0000234':
        substatus="'User is currently locked out'"
      elif substatus=='0xc0000072':
        substatus="'Account is currently disabled'"
      elif substatus=='0xc000006f':
        substatus="'User tried to logon outside his day of week or time of day restrictions'"
      elif substatus=='0xc0000070':
        substatus="'Workstation restriction, or Authentication Policy Silo violation (look for event ID 4820 on domain controller)'"
      elif substatus=='0xc0000193':
        substatus="'Account expiration'"
      elif substatus=='0xc0000071':
        substatus="'Expired password'"
      elif substatus=='0xc0000133':
        substatus="'Clocks between DC and other computer too far out of sync'"
      elif substatus=='0xc0000224':
        substatus="'User is required to change password at next logon'"
      elif substatus=='0xc0000225':
        substatus="'Evidently a bug in Windows and not a risk'"
      elif substatus=='0xc000015b':
        substatus="'The user has not been granted the requested logon type (aka logon right) at this machine'"

    if mapped_attr["Status"] in row:
      if isinstance(row[mapped_attr["Status"]],float):
        status=''
      else:
        status = row[mapped_attr["Status"]].replace('"','')
    else:
      status=''
    if status:
      status=hex(int(status))
      # If the status is related with the authentication
      if substatus!="":
        if status=='0xc000006d':
          status="'The attempted logon is invalid. This is either due to a bad username or authentication information.'"
      # If the status is related with the SuspiciousCreateSymbolicLink event
      elif row[mapped_attr["event_simpleName"]] in ("SuspiciousCreateSymbolicLink","FileOpenInfo","RansomwareOpenFile","NewExecutableWritten",'NewScriptWritten'):
        if status=='0x0':
          status="'Success'"
        elif status=='0x103':
          status="'Pending'"
        elif status=='0xc0000022':
          status="'Access denied'"
        elif status=='0x60120002':
          status="'No existing credentials'"
        elif status=='0x60110012':
          status="'Dep disabled appcompat'"
        elif status=='0xc000003d':
          status="'Data late error'"
        elif status=='0xe00e0028':
          status="'Process critical'"
        elif status=='0xe00e0029':
          status="'Process whitelisted'"
        elif status=='0xe00e002a':
          status="'Process Microsoft signed'"
        elif status=='0xe00e002b':
          status="'Process Apple signed'"
        elif status=='0x20140001':
          status="'Component enabled'"
        elif status=='0xe014003e':
          status="'Component disabled'"
        elif status=='0x60140016':
          status="'Component stopped'"
        elif status=='0x60190020':
          status="'HTTP visibility enabled'"
        elif status=='0x60190028':
          status="'SMTP visibility enabled'"
        elif status=='0x600e0021':
          status="'Mask adjusted'"
        elif status=='0x601e0024':
          status="'Already blocked'"
        elif status=='0xc000036b':
          status="'Driver blocked critical'"
        elif status=='0xC0000045':
          status="'Invalid page protection'"
        elif status=='0x102':
          status="'Timeout'"
        elif status=='0xc0000001':
          status="'Unsuccessful'"
        elif status=='0xc0000089':
          status="'Resource data not found'"
        elif status=='0xc000008b':
          status="'Resource name not found'"
        elif status=='0xc0000034':
          status="'Object name not found'"
        elif status=='0xc0000120':
          status="'Cancelled'"
        elif status=='0xc0000014':
          status="'Unrecognized media'"
        elif status=='0xe02500bb':
          status="'No active RPC thread'"
        elif status=='0xc000010a':
          status="'Process is terminating'"
        elif status=='0x122':
          status="'Nothing to terminate'"
        elif status=='0xc000029a':
          status="'Policy object not found'"
        elif status=='0xe0000027':
          status="'Process killed'"
        elif status=='0xc0000904':
          status="'File too large'"
        elif status=='0xc000000d':
          status="'Invalid parameter'"
        elif status=='0xc00000bb':
          status="'Not supported'"
        elif status=='0xc00000b5':
          status="'IO timeout'"

    if mapped_attr["UserSid"] in row:
      if isinstance(row[mapped_attr["UserSid"]],float):
        user_sid=''
      else:
        user_sid = row[mapped_attr["UserSid"]].replace('"','')
    else:
      user_sid=''
    if user_sid:
      user_sid=user_sid+' (read more: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)'

    if mapped_attr["UserPrincipal"] in row:
      if isinstance(row[mapped_attr["UserPrincipal"]],float):
        user_principal=''
      else:
        user_principal = row[mapped_attr["UserPrincipal"]].replace('"','')
    else:
      user_principal=''

    if mapped_attr["AuthenticationPackage"] in row:
      if isinstance(row[mapped_attr["AuthenticationPackage"]],float):
        authentication_package=''
      else:
        authentication_package = row[mapped_attr["AuthenticationPackage"]].replace('"','')
    else:
      authentication_package=''

    if mapped_attr["SymbolicLinkName"] in row:
      if isinstance(row[mapped_attr["SymbolicLinkName"]],float):
        symbolic_link_name=''
      else:
        symbolic_link_name = row[mapped_attr["SymbolicLinkName"]].replace('"','')
    else:
      symbolic_link_name=''

    if mapped_attr["SymbolicLinkTarget"] in row:
      if isinstance(row[mapped_attr["SymbolicLinkTarget"]],float):
        symbolic_link_target=''
      else:
        symbolic_link_target = row[mapped_attr["SymbolicLinkTarget"]].replace('"','')
    else:
      symbolic_link_target=''

    if mapped_attr["AsepClass"] in row:
      if isinstance(row[mapped_attr["AsepClass"]],float):
        asep_class=''
      else:
        asep_class = row[mapped_attr["AsepClass"]].replace('"','')
    else:
      asep_class=''
    if asep_class:
      asep_class=int(asep_class)
      if asep_class==0:
        asep_class="'Unknown'"
      elif asep_class==1:
        asep_class="'System startup autorun'"
      elif asep_class==2:
        asep_class="'System shutdown autorun'"
      elif asep_class==3:
        asep_class="'User logon autorun'"
      elif asep_class==4:
        asep_class="'User logoff autorun'"
      elif asep_class==5:
        asep_class="'Application start autorun'"
      elif asep_class==6:
        asep_class="'Application extension'"
      elif asep_class==7:
        asep_class="'Service'"
      elif asep_class==8:
        asep_class="'Authentication'"
      elif asep_class==9:
        asep_class="'Core processes'"
      elif asep_class==10:
        asep_class="'Custom processes'"
      elif asep_class==11:
        asep_class="'Core services'"
      elif asep_class==12:
        asep_class="'Core service plugins'"
      elif asep_class==13:
        asep_class="'Server plugins'"
      elif asep_class==14:
        asep_class="'Network service plugins'"
      elif asep_class==15:
        asep_class="'Lang service plugins'"
      elif asep_class==16:
        asep_class="'Multimedia plugins'"
      elif asep_class==17:
        asep_class="'Shell plugins'"
      elif asep_class==18:
        asep_class="'IE COM plugins'"
      elif asep_class==19:
        asep_class="'COM registration'"
      elif asep_class==20:
        asep_class="'Printers'"
      elif asep_class==21:
        asep_class="'Terminal server'"
      elif asep_class==22:
        asep_class="'Graphics core'"
      elif asep_class==23:
        asep_class="'System configuration'"
      elif asep_class==100:
        asep_class="'Boot configuration data (or ASEP class margin)'"
      elif asep_class==101:
        asep_class="'Crowdstrike key'"

    if mapped_attr["AsepFlags"] in row:
      if isinstance(row[mapped_attr["AsepFlags"]],float):
        asep_flags=''
      else:
        asep_flags = row[mapped_attr["AsepFlags"]].replace('"','')
    else:
      asep_flags=''
    if asep_flags:
      asep_flags=hex(int(asep_flags))
      input_hex_str=asep_flags
      hexadecimal_list = [
        {'key':0x1,'value':"'Global'"},
        {'key':0x2,'value':"'Privileged'"},
        {'key':0x4,'value':"'Needs source signed'"},
        {'key':0x8,'value':"'Needs target signed'"},
        {'key':0x10,'value':"'Needs source MS signed'"},
        {'key':0x20,'value':"'Needs target MS signed'"},
        {'key':0x40,'value':"'Suspicious'"}
      ]
      combinations = find_hex_combinations(input_hex_str, hexadecimal_list)
      asep_flags='('+(', '.join(combinations))+')'

    if mapped_attr["AsepIndex"] in row:
      if isinstance(row[mapped_attr["AsepIndex"]],float):
        asep_index=''
      else:
        asep_index = row[mapped_attr["AsepIndex"]].replace('"','')
    else:
      asep_index=''

    if mapped_attr["AsepValueType"] in row:
      if isinstance(row[mapped_attr["AsepValueType"]],float):
        asep_value_type=''
      else:
        asep_value_type = row[mapped_attr["AsepValueType"]].replace('"','')
    else:
      asep_value_type=''
    if asep_value_type:
      asep_value_type=int(asep_value_type)
      if asep_value_type==0:
        asep_value_type="'Unknown'"
      elif asep_value_type==1:
        asep_value_type="'Command line'"
      elif asep_value_type==2:
        asep_value_type="'DLL path'"
      elif asep_value_type==3:
        asep_value_type="'DLL name'"
      elif asep_value_type==4:
        asep_value_type="'Application name'"
      elif asep_value_type==5:
        asep_value_type="'GUID'"

    if mapped_attr["Data1"] in row:
      if isinstance(row[mapped_attr["Data1"]],float):
        asep_data1=''
      else:
        asep_data1 = row[mapped_attr["Data1"]].replace('"','')
    else:
      asep_data1=''

    if mapped_attr["RegObjectName"] in row:
      if isinstance(row[mapped_attr["RegObjectName"]],float):
        reg_object_name=''
      else:
        reg_object_name = row[mapped_attr["RegObjectName"]].replace('"','')
    else:
      reg_object_name=''

    if mapped_attr["RegOperationType"] in row:
      if isinstance(row[mapped_attr["RegOperationType"]],float):
        reg_operation_type=''
      else:
        reg_operation_type = row[mapped_attr["RegOperationType"]].replace('"','')
    else:
      reg_operation_type=''
    if reg_operation_type:
      reg_operation_type=int(reg_operation_type)
      if reg_operation_type==1:
        reg_operation_type="'Set value key'"
      elif reg_operation_type==2:
        reg_operation_type="'Delete value key'"
      elif reg_operation_type==3:
        reg_operation_type="'Create key'"
      elif reg_operation_type==4:
        reg_operation_type="'Delete key'"
      elif reg_operation_type==5:
        reg_operation_type="'Set key security'"
      elif reg_operation_type==6:
        reg_operation_type="'Load key'"
      elif reg_operation_type==7:
        reg_operation_type="'Rename key'"
      elif reg_operation_type==8:
        reg_operation_type="'Open key'"
      elif reg_operation_type==9:
        reg_operation_type="'Query name key'"
      elif reg_operation_type==101:
        reg_operation_type="'Set value key anti-tampering'"
      elif reg_operation_type==102:
        reg_operation_type="'Delete value key anti-tampering'"

    if mapped_attr["RegStringValue"] in row:
      if isinstance(row[mapped_attr["RegStringValue"]],float):
        reg_string_value=''
      else:
        reg_string_value = row[mapped_attr["RegStringValue"]].replace('"','')
    else:
      reg_string_value=''

    if mapped_attr["RegNumericValue"] in row:
      if isinstance(row[mapped_attr["RegNumericValue"]],float):
        reg_numeric_value=''
      else:
        reg_numeric_value = row[mapped_attr["RegNumericValue"]].replace('"','')
    else:
      reg_numeric_value=''

    if mapped_attr["RegBinaryValue"] in row:
      if isinstance(row[mapped_attr["RegBinaryValue"]],float):
        reg_binary_value=''
      else:
        reg_binary_value = row[mapped_attr["RegBinaryValue"]].replace('"','')
    else:
      reg_binary_value=''

    if mapped_attr["RegType"] in row:
      if isinstance(row[mapped_attr["RegType"]],float):
        reg_type=''
      else:
        reg_type = row[mapped_attr["RegType"]].replace('"','')
    else:
      reg_type=''
    if reg_type:
      reg_type=int(reg_type)
      if reg_type==0:
        reg_type="'None'"
      elif reg_type==1:
        reg_type="'SZ' (see https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types)"
      elif reg_type==2:
        reg_type="'Expand SZ' (see https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types)"
      elif reg_type==3:
        reg_type="'Binary'"
      elif reg_type==4:
        reg_type="'DWORD'"
      elif reg_type==5:
        reg_type="'DWORD big endian'"
      elif reg_type==6:
        reg_type="'Link' (see https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types)"
      elif reg_type==7:
        reg_type="'Multi SZ' (see https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types)"
      elif reg_type==8:
        reg_type="'Resource list'"
      elif reg_type==9:
        reg_type="'Full resource descriptor'"
      elif reg_type==10:
        reg_type="'Resource requirements list'"
      elif reg_type==11:
        reg_type="'QWORD'"

    if mapped_attr["RegValueName"] in row:
      if isinstance(row[mapped_attr["RegValueName"]],float):
        reg_value_name=''
      else:
        reg_value_name = row[mapped_attr["RegValueName"]].replace('"','')
    else:
      reg_value_name=''

    if mapped_attr["RegConfigClass"] in row:
      if isinstance(row[mapped_attr["RegConfigClass"]],float):
        reg_config_class=''
      else:
        reg_config_class = row[mapped_attr["RegConfigClass"]].replace('"','')
    else:
      reg_config_class=''
    if reg_config_class:
      reg_config_class=int(reg_config_class)
      if reg_config_class==0:
        reg_config_class="'Boot configuration data'"
      elif reg_config_class==1:
        reg_config_class="'Crowdstrike key'"

    if mapped_attr["RegConfigFlags"] in row:
      if isinstance(row[mapped_attr["RegConfigFlags"]],float):
        reg_config_flags=''
      else:
        reg_config_flags = row[mapped_attr["RegConfigFlags"]].replace('"','')
    else:
      reg_config_flags=''
    if reg_config_flags:
      reg_config_flags=hex(int(reg_config_flags))
      input_hex_str=reg_config_flags
      hexadecimal_list = [
        {'key':0x1,'value':"'Global'"},
        {'key':0x4,'value':"'Needs source signed'"},
        {'key':0x10,'value':"'Needs target MS signed'"},
        {'key':0x40,'value':"'Suspicious'"}
      ]
      combinations = find_hex_combinations(input_hex_str, hexadecimal_list)
      reg_config_flags='('+(', '.join(combinations))+')'

    if mapped_attr["RegConfigIndex"] in row:
      if isinstance(row[mapped_attr["RegConfigIndex"]],float):
        reg_config_index=''
      else:
        reg_config_index = row[mapped_attr["RegConfigIndex"]].replace('"','')
    else:
      reg_config_index=''

    if mapped_attr["RegConfigValueType"] in row:
      if isinstance(row[mapped_attr["RegConfigValueType"]],float):
        reg_config_value_type=''
      else:
        reg_config_value_type = row[mapped_attr["RegConfigValueType"]].replace('"','')
    else:
      reg_config_value_type=''
    if reg_config_value_type:
      reg_config_value_type=int(reg_config_value_type)
      if reg_config_value_type==0:
        reg_config_value_type="'Unknown'"

    if mapped_attr["TargetCommandLineParameters"] in row:
      if isinstance(row[mapped_attr["TargetCommandLineParameters"]],float):
        target_command_line_parameters=''
      else:
        target_command_line_parameters = row[mapped_attr["TargetCommandLineParameters"]].replace('"','')
    else:
      target_command_line_parameters=''

    if mapped_attr["TargetSHA256HashData"] in row:
      if isinstance(row[mapped_attr["TargetSHA256HashData"]],float):
        target_sha256_hash_data=''
      else:
        target_sha256_hash_data = row[mapped_attr["TargetSHA256HashData"]].replace('"','')
    else:
      target_sha256_hash_data=''

    if mapped_attr["ScriptContent"] in row:
      if isinstance(row[mapped_attr["ScriptContent"]],float):
        script_content=''
      else:
        script_content = row[mapped_attr["ScriptContent"]].replace('"','')
    else:
      script_content=''

    if mapped_attr["ContentSHA256HashData"] in row:
      if isinstance(row[mapped_attr["ContentSHA256HashData"]],float):
        content_sha256=''
      else:
        content_sha256 = row[mapped_attr["ContentSHA256HashData"]].replace('"','')
    else:
      content_sha256=''

    if mapped_attr["HostProcessType"] in row:
      if isinstance(row[mapped_attr["HostProcessType"]],float):
        host_process_type=''
      else:
        host_process_type = row[mapped_attr["HostProcessType"]].replace('"','')
    else:
      host_process_type=''

    if mapped_attr["ScriptContentName"] in row:
      if isinstance(row[mapped_attr["ScriptContentName"]],float):
        script_content_name=''
      else:
        script_content_name = row[mapped_attr["ScriptContentName"]].replace('"','')
    else:
      script_content_name=''

    if mapped_attr["ScriptContentSource"] in row:
      if isinstance(row[mapped_attr["ScriptContentSource"]],float):
        script_content_source=''
      else:
        script_content_source = row[mapped_attr["ScriptContentSource"]].replace('"','')
    else:
      script_content_source=''
    if script_content_source:
      script_content_source=int(script_content_source)
      if script_content_source==0:
        script_content_source="'Inconclusive'"
      elif script_content_source==1:
        script_content_source="'File'"
      elif script_content_source==2:
        script_content_source="'Command'"
      elif script_content_source==3:
        script_content_source="'Encoded command'"
      elif script_content_source==4:
        script_content_source="'STDIN'"
      elif script_content_source==5:
        script_content_source="'Dynamic'"
      elif script_content_source==6:
        script_content_source="'Interactive'"

    if mapped_attr["ScriptingLanguageId"] in row:
      if isinstance(row[mapped_attr["ScriptingLanguageId"]],float):
        scripting_language_id=''
      else:
        scripting_language_id = row[mapped_attr["ScriptingLanguageId"]].replace('"','')
    else:
      scripting_language_id=''
    if scripting_language_id:
      scripting_language_id=int(scripting_language_id)
      if scripting_language_id==1:
        scripting_language_id="'Unknown'"
      elif scripting_language_id==2:
        scripting_language_id="'Powershell'"
      elif scripting_language_id==3:
        scripting_language_id="'VBA'"
      elif scripting_language_id==4:
        scripting_language_id="'VBScript'"
      elif scripting_language_id==5:
        scripting_language_id="'JScript'"
      elif scripting_language_id==6:
        scripting_language_id="'Dotnet'"
      elif scripting_language_id==7:
        scripting_language_id="'Excel'"

    if mapped_attr["TemplateInstanceId"] in row:
      if isinstance(row[mapped_attr["TemplateInstanceId"]],float):
        template_instance_id=''
      else:
        template_instance_id = row[mapped_attr["TemplateInstanceId"]].replace('"','')
    else:
      template_instance_id=''

    if mapped_attr["SHA256HashData"] in row and row[mapped_attr["SHA256HashData"]]!='""' and row[mapped_attr["SHA256HashData"]]:
      if isinstance(row[mapped_attr["SHA256HashData"]],float):
        if math.isnan(row[mapped_attr["SHA256HashData"]]):
          sha256=''
        else:
          sha256=row[mapped_attr["SHA256HashData"]].replace('"','')
      else:
        sha256=row[mapped_attr["SHA256HashData"]].replace('"','')
    else:
      sha256=''

    if mapped_attr["SHA1HashData"] in row and row[mapped_attr["SHA1HashData"]]!='""' and row[mapped_attr["SHA1HashData"]]:
      if isinstance(row[mapped_attr["SHA1HashData"]],float):
        if math.isnan(row[mapped_attr["SHA1HashData"]]):
          sha1=''
        else:
          sha1=row[mapped_attr["SHA1HashData"]].replace('"','')
      else:
        sha1=row[mapped_attr["SHA1HashData"]].replace('"','')
    else:
      sha1=''

    if mapped_attr["MD5HashData"] in row and row[mapped_attr["MD5HashData"]]!='""' and row[mapped_attr["MD5HashData"]]:
      if isinstance(row[mapped_attr["MD5HashData"]],float):
        if math.isnan(row[mapped_attr["MD5HashData"]]):
          md5=''
        else:
          md5=row[mapped_attr["MD5HashData"]].replace('"','')
      else:
        md5=row[mapped_attr["MD5HashData"]].replace('"','')
    else:
      md5=''

    if mapped_attr["InjectedThreadFlag"] in row and row[mapped_attr["InjectedThreadFlag"]]!='""' and row[mapped_attr["InjectedThreadFlag"]]:
      if isinstance(row[mapped_attr["InjectedThreadFlag"]],float):
        if math.isnan(row[mapped_attr["InjectedThreadFlag"]]):
          injected_thread_flag=''
        else:
          injected_thread_flag=row[mapped_attr["InjectedThreadFlag"]].replace('"','')
      else:
        injected_thread_flag=row[mapped_attr["InjectedThreadFlag"]].replace('"','')
    else:
      injected_thread_flag=''
    if injected_thread_flag:
      injected_thread_flag=hex(int(injected_thread_flag))
      input_hex_str=injected_thread_flag
      hexadecimal_list = [
        {'key':0x0,'value':"'None'"},
        {'key':0x1,'value':"'PREV_MODE_KERNEL'"},
        {'key':0x2,'value':"'START_ADDRESS_IN_NAMED_PE'"},
        {'key':0x4,'value':"'START_ADDRESS_IN_SYS_RANGE'"},
        {'key':0x8,'value':"'System thread'"},
        {'key':0x10,'value':"'Source thread in system'"},
        {'key':0x20,'value':"'Target analysis failed'"},
        {'key':0x40,'value':"'Context analysis failed'"},
        {'key':0x80,'value':"'START_ADDRESS_IN_NTDLL'"},
        {'key':0x100,'value':"'START_ADDRESS_IN_WIN_DLL'"},
        {'key':0x200,'value':"'START_ADDRESS_PRIVATE_MEM'"}
      ]
      combinations = find_hex_combinations(input_hex_str, hexadecimal_list)
      injected_thread_flag='('+(', '.join(combinations))+')'

    if mapped_attr["TargetThreadModule"] in row and row[mapped_attr["TargetThreadModule"]]!='""' and row[mapped_attr["TargetThreadModule"]]:
      if isinstance(row[mapped_attr["TargetThreadModule"]],float):
        if math.isnan(row[mapped_attr["TargetThreadModule"]]):
          target_thread_module=''
        else:
          target_thread_module=row[mapped_attr["TargetThreadModule"]].replace('"','')
      else:
        target_thread_module=row[mapped_attr["TargetThreadModule"]].replace('"','')
    else:
      target_thread_module=''

    if mapped_attr["InjecteeImageFileName"] in row and row[mapped_attr["InjecteeImageFileName"]]!='""' and row[mapped_attr["InjecteeImageFileName"]]:
      if isinstance(row[mapped_attr["InjecteeImageFileName"]],float):
        if math.isnan(row[mapped_attr["InjecteeImageFileName"]]):
          injectee_image_file_name=''
        else:
          injectee_image_file_name=row[mapped_attr["InjecteeImageFileName"]].replace('"','')
      else:
        injectee_image_file_name=row[mapped_attr["InjecteeImageFileName"]].replace('"','')
    else:
      injectee_image_file_name=''

    if mapped_attr["InjectorImageFileName"] in row and row[mapped_attr["InjectorImageFileName"]]!='""' and row[mapped_attr["InjectorImageFileName"]]:
      if isinstance(row[mapped_attr["InjectorImageFileName"]],float):
        if math.isnan(row[mapped_attr["InjectorImageFileName"]]):
          injector_image_file_name=''
        else:
          injector_image_file_name=row[mapped_attr["InjectorImageFileName"]].replace('"','')
      else:
        injector_image_file_name=row[mapped_attr["InjectorImageFileName"]].replace('"','')
    else:
      injector_image_file_name=''

    if mapped_attr["MemoryDescriptionFlags"] in row and row[mapped_attr["MemoryDescriptionFlags"]]!='""' and row[mapped_attr["MemoryDescriptionFlags"]]:
      if isinstance(row[mapped_attr["MemoryDescriptionFlags"]],float):
        if math.isnan(row[mapped_attr["MemoryDescriptionFlags"]]):
          memory_description_flags=''
        else:
          memory_description_flags=row[mapped_attr["MemoryDescriptionFlags"]].replace('"','')
      else:
        memory_description_flags=row[mapped_attr["MemoryDescriptionFlags"]].replace('"','')
    else:
      memory_description_flags=''

    if mapped_attr["ModuleName"] in row and row[mapped_attr["ModuleName"]]!='""' and row[mapped_attr["ModuleName"]]:
      if isinstance(row[mapped_attr["ModuleName"]],float):
        if math.isnan(row[mapped_attr["ModuleName"]]):
          module_name=''
        else:
          module_name=row[mapped_attr["ModuleName"]].replace('"','')
      else:
        module_name=row[mapped_attr["ModuleName"]].replace('"','')
    else:
      module_name=''

    if mapped_attr["ThreadExecutionControlType"] in row and row[mapped_attr["ThreadExecutionControlType"]]!='""' and row[mapped_attr["ThreadExecutionControlType"]]:
      if isinstance(row[mapped_attr["ThreadExecutionControlType"]],float):
        if math.isnan(row[mapped_attr["ThreadExecutionControlType"]]):
          thread_execution_control_type=''
        else:
          thread_execution_control_type=row[mapped_attr["ThreadExecutionControlType"]].replace('"','')
      else:
        thread_execution_control_type=row[mapped_attr["ThreadExecutionControlType"]].replace('"','')
    else:
      thread_execution_control_type=''
    if thread_execution_control_type:
      thread_execution_control_type=int(thread_execution_control_type)
      if thread_execution_control_type==0:
        thread_execution_control_type="'Thread inject'"
      elif thread_execution_control_type==1:
        thread_execution_control_type="'Thread inject masquerade'"
      elif thread_execution_control_type==2:
        thread_execution_control_type="'thread hijack'"
      elif thread_execution_control_type==3:
        thread_execution_control_type="'process hollowing'"
      elif thread_execution_control_type==4:
        thread_execution_control_type="'Windows hook'"
      elif thread_execution_control_type==5:
        thread_execution_control_type="'Process overwrite hollowing'"
      elif thread_execution_control_type==6:
        thread_execution_control_type="'Remote APC'"
      elif thread_execution_control_type==7:
        thread_execution_control_type="'Remote atom bomb'"
      elif thread_execution_control_type==8:
        thread_execution_control_type="'Process hollowing APC'"
      elif thread_execution_control_type==9:
        thread_execution_control_type="'Set window long'"
      elif thread_execution_control_type==10:
        thread_execution_control_type="'SET_PROP'"

    if mapped_attr["WellKnownTargetFunction"] in row and row[mapped_attr["WellKnownTargetFunction"]]!='""' and row[mapped_attr["WellKnownTargetFunction"]]:
      if isinstance(row[mapped_attr["WellKnownTargetFunction"]],float):
        if math.isnan(row[mapped_attr["WellKnownTargetFunction"]]):
          well_known_target_function=''
        else:
          well_known_target_function=row[mapped_attr["WellKnownTargetFunction"]].replace('"','')
      else:
        well_known_target_function=row[mapped_attr["WellKnownTargetFunction"]].replace('"','')
    else:
      well_known_target_function=''
    if well_known_target_function:
      well_known_target_function=int(well_known_target_function)
      if well_known_target_function==0:
        well_known_target_function="'Unknown'"
      elif well_known_target_function==1:
        well_known_target_function="'LOAD_LIBRARY_A'"
      elif well_known_target_function==2:
        well_known_target_function="'LOAD_LIBRARY_W'"
      elif well_known_target_function==3:
        well_known_target_function="'GLOBAL_GET_ATOM_NAME_A'"
      elif well_known_target_function==4:
        well_known_target_function="'GLOBAL_GET_ATOM_NAME_W'"
      elif well_known_target_function==5:
        well_known_target_function="'RTL_DISPATCH_APC'"

    if mapped_attr["ExecutableBytes"] in row and row[mapped_attr["ExecutableBytes"]]!='""' and row[mapped_attr["ExecutableBytes"]]:
      if isinstance(row[mapped_attr["ExecutableBytes"]],float):
        if math.isnan(row[mapped_attr["ExecutableBytes"]]):
          executable_bytes=''
        else:
          executable_bytes=row[mapped_attr["ExecutableBytes"]].replace('"','')
      else:
        executable_bytes=row[mapped_attr["ExecutableBytes"]].replace('"','')
    else:
      executable_bytes=''

    context={}
    context['EVENT_SIMPLE_NAME'] = row[mapped_attr["event_simpleName"]]
    context['PROCESS_INSTANT'] = dt_instant
    context['CONTEXT_ID'] = context_id
    context['TARGET_FILE_NAME']= target_file_name
    context['IMAGE_FILE_NAME']= image_file_name
    context['LOCAL_ADDRESS_IP4']= local_address_ip4
    context['LOCAL_ADDRESS_IP6']= local_address_ip6
    context['LOCAL_PORT']= local_port
    context['REMOTE_ADDRESS_IP4']= remote_address_ip4
    context['REMOTE_ADDRESS_IP6']= remote_address_ip6
    context['REMOTE_PORT']= remote_port
    context['DOMAIN_NAME']= domain_name
    context['REQUEST_TYPE']= request_type
    context['CNAME_RECORDS']= cname_records
    context['IP4_RECORDS']= ip4_records
    context['IP6_RECORDS']= ip6_records
    context['PROTOCOL']= protocol
    context['SERVICE_DISPLAY_NAME']= service_display_name
    context['SERVICE_DESCRIPTION']= service_description
    context['SERVICE_IMAGE_PATH']= service_image_path
    context['SERVICE_OBJECT_NAME']= service_object_name
    context['SERVICE_ERROR_CONTROL']= service_error_control
    context['SERVICE_START']= service_start
    context['SERVICE_TYPE']= service_type
    context['TOKEN_TYPE']= token_type
    context['QUERY_STATUS']= query_status
    context['HTTP_METHOD']= http_method
    context['HTTP_HOST']= http_host
    context['HTTP_PATH']= http_path
    context['ENVIRONMENT_VARIABLE_NAME']= environment_variable_name
    context['ENVIRONMENT_VARIABLE_VALUE']= environment_variable_value
    context['LOGON_TIME']= logon_time
    context['LOGOFF_TIME']= logoff_time
    context['LOGON_TYPE']= logon_type
    context['PASSWORD_LAST_SET']= password_last_set
    context['USERISADMIN']= user_is_admin
    context['REMOTE_ACCOUNT']= remote_account
    context['USERNAME']= username
    context['USER_PRINCIPAL']= user_principal
    context['USER_SID']= user_sid
    context['AUTHENTICATION_ID']= authentication_id
    context['SESSION_ID']= session_id
    context['AUTHENTICATION_PACKAGE']= authentication_package
    context['STATUS']= status
    context['SUBSTATUS']= substatus
    context['LOGON_DOMAIN']= logon_domain
    context['LOGON_SERVER']= logon_server
    context['LOGON_FLAGS']= logon_flags
    context['CLIENT_COMPUTER_NAME']= client_computer_name
    context['SYMBOLIC_LINK_NAME']= symbolic_link_name
    context['SYMBOLIC_LINK_TARGET']= symbolic_link_target
    context['ASEP_CLASS']= asep_class
    context['ASEP_FLAGS']= asep_flags
    context['ASEP_INDEX']= asep_index
    context['ASEP_VALUE_TYPE']= asep_value_type
    context['DATA1']= asep_data1
    context['REG_OBJECT_NAME']= reg_object_name
    context['REG_OPERATION_TYPE']= reg_operation_type
    context['REG_STRING_VALUE']= reg_string_value
    context['REG_NUMERIC_VALUE']= reg_numeric_value
    context['REG_BINARY_VALUE']= reg_binary_value
    context['REG_TYPE']= reg_type
    context['REG_VALUE_NAME']= reg_value_name
    context['REG_CONFIG_CLASS']= reg_config_class
    context['REG_CONFIG_FLAGS']= reg_config_flags
    context['REG_CONFIG_INDEX']= reg_config_index
    context['REG_CONFIG_VALUE_TYPE']= reg_config_value_type
    context['TARGET_COMMAND_LINE_PARAMETERS']= target_command_line_parameters
    context['TARGET_SHA256_HASH_DATA']= target_sha256_hash_data
    context['SCRIPT_CONTENT']= script_content
    context['CONTENT_SHA256']= content_sha256
    context['HOST_PROCESS_TYPE']= host_process_type
    context['SCRIPT_CONTENT_NAME']= script_content_name
    context['SCRIPT_CONTENT_SOURCE']= script_content_source
    context['SCRIPTING_LANGUAGE_ID']= scripting_language_id
    context['TEMPLATE_INSTANCE_ID']= template_instance_id
    context['SOURCE_FILE_NAME']= source_file_name
    context['SIZE']= size
    context['IS_ON_REMOVABLE_DISK']= is_on_removable_disk
    context['IS_ON_NETWORK']= is_on_network
    context['MD5']= md5
    context['SHA1']= sha1
    context['SHA256']= sha256
    context['INJECTED_THREAD_FLAG']= injected_thread_flag
    context['TARGET_THREAD_MODULE']= target_thread_module
    context['INJECTEE_IMAGE_FILE_NAME']= injectee_image_file_name
    context['INJECTOR_IMAGE_FILE_NAME']= injector_image_file_name
    context['MEMORY_DESCRIPTION_FLAGS']= memory_description_flags
    context['MODULE_NAME']= module_name
    context['THREAD_EXECUTION_CONTROL_TYPE']= thread_execution_control_type
    context['WELL_KNOWN_TARGET_FUNCTION']= well_known_target_function
    context['EXECUTABLE_BYTES']= executable_bytes
    context['TARGET_PROCESS_ID']= target_process_id
    context['TARGET_THREAD_ID']= target_thread_id
    # Update the process details
    # When a context exists
    if context_id and dt_instant:
      #print(context_id,context)
      # Context with an existing process
      if context_id in processes:
        processes[context_id]['Context'].append(context)
      # A context without an existing process
      else:
        processes[context_id]={}
        processes[context_id]['AID'] = row[mapped_attr["aid"]]
        processes[context_id]['EVENT_SIMPLE_NAME'] = 'PotentialProcessRollup2'
        processes[context_id]['COMMAND_LINE'] = 'unknown'
        processes[context_id]['SHA256'] = 'unknown'
        processes[context_id]['SHA1'] = 'unknown'
        processes[context_id]['MD5'] = 'unknown'
        processes[context_id]['PARENT_PROCESS_ID'] = '0'
        processes[context_id]['PROCESS_START_TIME'] = '0'
        processes[context_id]['PROCESS_END_TIME'] = '0'
        processes[context_id]['PROCESS_DURATION_TIME'] = 'undetermined'
        processes[context_id]['AUTHENTICATION_ID'] = 'unknown'
        processes[context_id]['PARENT_AUTHENTICATION_ID'] = 'unknown'
        processes[context_id]['SESSION_ID'] = 'unknown'
        processes[context_id]['USER_SID'] = 'unknown'
        processes[context_id]['TOKEN_TYPE'] = 'unknown'
        processes[context_id]['IMAGE_FILE_NAME'] = 'unknown'
        processes[context_id]['Children'] = []
        processes[context_id]['Context'] = []
        processes[context_id]['Context'].append(context)
        if context_id not in all_ids:
          all_ids.append(context_id)
        if context_id not in root_process_ids:
          root_process_ids.append(context_id)
        #print(processes[context_id])
        #print(root_process_ids)
    # When a context doesn't exist
    elif context_id=='':
      if row[mapped_attr["aid"]] in authentications and 'Context' in authentications[row[mapped_attr["aid"]]]:
        authentications[row[mapped_attr["aid"]]]['Context'].append(context)
      else:
        authentications[row[mapped_attr["aid"]]]={}
        authentications[row[mapped_attr["aid"]]]['Context']=[]
        authentications[row[mapped_attr["aid"]]]['Context'].append(context)

    # Update the process details
    if rpc_client_process_id and dt_instant:
      #print(rpc_client_process_id,context)
      # Context with an existing process
      if rpc_client_process_id in processes:
        processes[rpc_client_process_id]['Context'].append(context)
      # A context without an existing process
      else:
        processes[rpc_client_process_id]={}
        processes[rpc_client_process_id]['AID'] = row[mapped_attr["aid"]]
        processes[rpc_client_process_id]['EVENT_SIMPLE_NAME'] = 'PotentialProcessRollup2'
        processes[rpc_client_process_id]['COMMAND_LINE'] = 'unknown'
        processes[rpc_client_process_id]['SHA256'] = 'unknown'
        processes[rpc_client_process_id]['SHA1'] = 'unknown'
        processes[rpc_client_process_id]['MD5'] = 'unknown'
        processes[rpc_client_process_id]['PARENT_PROCESS_ID'] = '0'
        processes[rpc_client_process_id]['PROCESS_START_TIME'] = '0'
        processes[rpc_client_process_id]['PROCESS_END_TIME'] = '0'
        processes[rpc_client_process_id]['PROCESS_DURATION_TIME'] = 'undetermined'
        processes[rpc_client_process_id]['AUTHENTICATION_ID'] = 'unknown'
        processes[rpc_client_process_id]['PARENT_AUTHENTICATION_ID'] = 'unknown'
        processes[rpc_client_process_id]['SESSION_ID'] = 'unknown'
        processes[rpc_client_process_id]['USER_SID'] = 'unknown'
        processes[rpc_client_process_id]['TOKEN_TYPE'] = 'unknown'
        processes[rpc_client_process_id]['IMAGE_FILE_NAME'] = 'unknown'
        processes[rpc_client_process_id]['Children'] = []
        processes[rpc_client_process_id]['Context'] = []
        processes[rpc_client_process_id]['Context'].append(context)
        if rpc_client_process_id not in all_ids:
          all_ids.append(rpc_client_process_id)
        if rpc_client_process_id not in root_process_ids:
          root_process_ids.append(rpc_client_process_id)
        #print(processes[rpc_client_process_id])
        #print(root_process_ids)
    elif rpc_client_process_id=='':
      if row[mapped_attr["aid"]] in authentications and 'Context' in authentications[row[mapped_attr["aid"]]]:
        authentications[row[mapped_attr["aid"]]]['Context'].append(context)
      else:
        authentications[row[mapped_attr["aid"]]]={}
        authentications[row[mapped_attr["aid"]]]['Context']=[]
        authentications[row[mapped_attr["aid"]]]['Context'].append(context)


# This part is obsolete and it was replaced with the next loop section because the inexistant process IDs became personalized
#for index, row in df.iterrows():
#  if row[mapped_attr["event_simpleName"]] in processes_events:
#    if mapped_attr["TargetProcessId"] in row and row[mapped_attr["TargetProcessId"]]!='""' and row[mapped_attr["TargetProcessId"]]:
#      if isinstance(row[mapped_attr["TargetProcessId"]],float):
#        if math.isnan(row[mapped_attr["TargetProcessId"]]):
#          process_id=''
#        else:
#          process_id = row[mapped_attr["TargetProcessId"]].replace('"','')
#      else:
#        process_id = row[mapped_attr["TargetProcessId"]].replace('"','')
#    else:
#      process_id=''

#    if mapped_attr["ParentProcessId"] in row and row[mapped_attr["ParentProcessId"]]!='""' and row[mapped_attr["ParentProcessId"]]:
#      if isinstance(row[mapped_attr["ParentProcessId"]],float):
#        if math.isnan(row[mapped_attr["ParentProcessId"]]):
#          parent_id=''
#        else:
#          parent_id = row[mapped_attr["ParentProcessId"]].replace('"','')
#      else:
#        parent_id = row[mapped_attr["ParentProcessId"]].replace('"','')
#    else:
#      parent_id=''

copy_processes=processes.copy()
for index, row in copy_processes.items():
  process_id=index
  parent_id=processes[process_id]['PARENT_PROCESS_ID']
  if processes[process_id]['EVENT_SIMPLE_NAME'] in processes_events:
    # If parentProcessID exists, add the current process as a child to the parent
    if not pd.isnull(parent_id):
        #parent_id = int(parent_id)
        if parent_id not in processes:
            processes[parent_id]={}
            processes[parent_id]['AID'] = row[mapped_attr["aid"]]
            processes[parent_id]['EVENT_SIMPLE_NAME'] = 'PotentialProcessRollup2'
            processes[parent_id]['COMMAND_LINE'] = 'unknown'
            processes[parent_id]['SHA256'] = 'unknown'
            processes[parent_id]['SHA1'] = 'unknown'
            processes[parent_id]['MD5'] = 'unknown'
            processes[parent_id]['PARENT_PROCESS_ID'] = '0'
            processes[parent_id]['PROCESS_START_TIME'] = '0'
            processes[parent_id]['PROCESS_END_TIME'] = '0'
            processes[parent_id]['PROCESS_DURATION_TIME'] = 'undetermined'
            processes[parent_id]['AUTHENTICATION_ID'] = 'unknown'
            processes[parent_id]['PARENT_AUTHENTICATION_ID'] = 'unknown'
            processes[parent_id]['SESSION_ID'] = 'unknown'
            processes[parent_id]['USER_SID'] = 'unknown'
            processes[parent_id]['TOKEN_TYPE'] = 'unknown'
            processes[parent_id]['IMAGE_FILE_NAME'] = 'unknown'
            processes[parent_id]['Children'] = []
            processes[parent_id]['Context'] = []
            if parent_id not in root_process_ids:
                root_process_ids.append(parent_id)
        if process_id not in processes[parent_id]['Children']:
          processes[parent_id]['Children'].append(process_id)

# Some process IDs popup from the parent process ID column and thus the df object is no longer providing the full list of process IDs
for index, row in processes.items():
  if "PARENT_PROCESS_ID" in processes[index] and processes[index]["PARENT_PROCESS_ID"]!='0' and index in root_process_ids:
    root_process_ids.remove(index)

# Function to recursively print the process tree
def print_process_tree(process_id, indent='-->'):
    if process_id in processes:
        #print(processes[process_id])
        #if '69913571672933'==process_id:
        #  print(processes[process_id])
        #  exit()
        process_details = processes[process_id]
        single_process_printed=""
        single_process_in_a_graph={
          "label":"",
          "id":str(process_id),"attributes":{},"color":"rgb(175,156,171)",
          "size":15
        }
        single_process_in_a_tree={
            "name": "unknown",
            "id": process_id,
            "details": single_process_printed,
            "context": [],
            "children": []
        }
        if process_details['EVENT_SIMPLE_NAME'] in ('ProcessRollup2','SyntheticProcessRollup2'):
          event_description='\033[33mProcess executed\033[0m'
          event_description2='<span style="color:#fd8d3c">Process executed</span>'
          #event_description3='<tspan fill="#fd8d3c" dx="0" dy="0">Process executed</tspan>'
        elif process_details['EVENT_SIMPLE_NAME'] in ('ProcessBlocked'):
          event_description='>>!!!\033[33mProcessBlocked\033[0m!!!<<  ᕙ(⇀‸↼‶)ᕗ'
          event_description2='>>!!!<span style="color:red">ProcessBlocked</span>!!!<<  ᕙ(⇀‸↼‶)ᕗ'
          #event_description3='>>!!!<tspan fill="red" dx="0" dy="0">ProcessBlocked</tspan>!!!<<  ᕙ(⇀‸↼‶)ᕗ'
        elif process_details['EVENT_SIMPLE_NAME'] in ('PotentialProcessRollup2'):
          event_description='\033[33mUnknown process executed\033[0m'
          event_description2='<span style="color:#fd8d3c">Unknown process executed</span>'
          #event_description3='<tspan fill="#fd8d3c" dx="0" dy="0">Unknown process executed</tspan>'
        else:
          event_description=process_details['EVENT_SIMPLE_NAME']
          event_description2='<span style="color:#fd8d3c">'+process_details['EVENT_SIMPLE_NAME']+'</span>'
          #event_description3='<tspan fill="#fd8d3c" dx="0" dy="0">'+process_details['EVENT_SIMPLE_NAME']+'</tspan>'
        print(f'{indent}Process (ID:{process_id}) (since {process_details["PROCESS_START_TIME"]} during {process_details["PROCESS_DURATION_TIME"]} period)   {event_description}:')
        single_process_printed=f'Process (ID:{process_id}) (since {process_details["PROCESS_START_TIME"]} during {process_details["PROCESS_DURATION_TIME"]} period)   {event_description2}:<br/>'
        indent2=indent.replace('-->','    ')
        if process_details['EVENT_SIMPLE_NAME']=='CommandHistory':
          print(f'{indent2}Command lines: \n{process_details["COMMAND_LINE"]}')
          single_process_printed=single_process_printed+f'Command lines: \n{process_details["COMMAND_LINE"]}<br/>'
        else:
          print(f'{indent2}Command line: {process_details["COMMAND_LINE"]}')
          single_process_printed=single_process_printed+f'Command line: {process_details["COMMAND_LINE"]}<br/>'
          if "IMAGE_FILE_NAME" in process_details and process_details["IMAGE_FILE_NAME"]!='' and process_details["IMAGE_FILE_NAME"]!='unknown':
            print(f'{indent2}Executable path: {process_details["IMAGE_FILE_NAME"]}')
            single_process_printed=single_process_printed+f'Executable path: {process_details["IMAGE_FILE_NAME"]}<br/>'
            single_process_in_a_graph["label"]=process_details["IMAGE_FILE_NAME"].split("\\")[-1]
            single_process_in_a_tree["name"]=process_details["IMAGE_FILE_NAME"].split("\\")[-1]
          if "MD5" in process_details and process_details["MD5"]!='' and process_details["MD5"]!='unknown':
            print(f'{indent2}Hash (MD5): {process_details["MD5"]}')
            single_process_printed=single_process_printed+f'Hash (MD5): {process_details["MD5"]}<br/>'
          if "SHA1" in process_details and process_details["SHA1"]!="0000000000000000000000000000000000000000" and process_details["SHA1"]!='' and process_details["SHA1"]!='unknown':
            print(f'{indent2}Hash (SHA1): {process_details["SHA1"]}')
            single_process_printed=single_process_printed+f'Hash (SHA1): {process_details["SHA1"]}<br/>'
          if "SHA256" in process_details and process_details["SHA256"]!='' and process_details["SHA256"]!='unknown':
            print(f'{indent2}Hash (SHA256): {process_details["SHA256"]}')
            single_process_printed=single_process_printed+f'Hash (SHA256): {process_details["SHA256"]}<br/>'
          tmp=[]
          if "AUTHENTICATION_ID" in process_details and process_details["AUTHENTICATION_ID"]!='' and process_details["AUTHENTICATION_ID"]!='unknown':
             tmp.append(f'AuthenticationID: {process_details["AUTHENTICATION_ID"]}')
          if "USER_SID" in process_details and process_details["USER_SID"]!='' and process_details["USER_SID"]!='unknown':
             tmp.append(f'SID: {process_details["USER_SID"]}')
          if "TOKEN_TYPE" in process_details and process_details["TOKEN_TYPE"]!='' and process_details["TOKEN_TYPE"]!='unknown':
             tmp.append(f'Token type: {process_details["TOKEN_TYPE"]}')
          if len(tmp)>0:
            print(f'{indent2}'+(', '.join(tmp)))
            new_tmp=(', '.join(tmp)).replace("https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers","<a href='https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers'>here</a>")
            single_process_printed=single_process_printed+new_tmp+'<br/>'



        #print(process_details["Context"])
        if len(process_details["Context"])>0:
          for context in process_details["Context"]:
            context_details_str=""
            context_details_str2=""
            indent3=indent.replace('-->','    ')+'-->'
            if context['EVENT_SIMPLE_NAME']=='ModuleBlockedEvent':
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   >>!!!\033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m!!!<<  ᕙ(⇀‸↼‶)ᕗ:\n'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   >>!!!<span style="color:red">{context["EVENT_SIMPLE_NAME"]}</span>!!!<<  ᕙ(⇀‸↼‶)ᕗ:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}{context["TARGET_FILE_NAME"]}\n'
              context_details_str2=context_details_str2+f'{context["TARGET_FILE_NAME"]}<br/>'
            elif context['EVENT_SIMPLE_NAME']=='ModuleBlockedEventWithPatternId':
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   >>!!!\033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m!!!<<  ᕙ(⇀‸↼‶)ᕗ:\n'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   >>!!!<span style="color:red">{context["EVENT_SIMPLE_NAME"]}</span>!!!<<  ᕙ(⇀‸↼‶)ᕗ:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}{context["TARGET_FILE_NAME"]}\n'
              context_details_str2=context_details_str2+f'{context["TARGET_FILE_NAME"]}<br/>'
            elif context['EVENT_SIMPLE_NAME'] in ('ScriptControlBlocked'):
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   >>!!!\033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m!!!<<  ᕙ(⇀‸↼‶)ᕗ:\n'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   >>!!!<span style="color:red">{context["EVENT_SIMPLE_NAME"]}</span>!!!<<  ᕙ(⇀‸↼‶)ᕗ:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}Script content source: {context["SCRIPT_CONTENT_SOURCE"]}\n'
              context_details_str2=context_details_str2+f'Script content source: {context["SCRIPT_CONTENT_SOURCE"]}<br/>'
              if "SCRIPT_CONTENT_NAME" in context and context["SCRIPT_CONTENT_NAME"]!="":
                context_details_str=context_details_str+f'{indent4}Script content name: {context["SCRIPT_CONTENT_NAME"]}\n'
                context_details_str2=context_details_str2+f'Script content name: {context["SCRIPT_CONTENT_NAME"]}<br/>'
              context_details_str=context_details_str+f'{indent4}Script language: {context["SCRIPTING_LANGUAGE_ID"]}, Script template ID: {context["TEMPLATE_INSTANCE_ID"]}\n'
              context_details_str2=context_details_str2+f'Script language: {context["SCRIPTING_LANGUAGE_ID"]}, Script template ID: {context["TEMPLATE_INSTANCE_ID"]}<br/>'
              context_details_str=context_details_str+f'{indent4}Script content: {context["SCRIPT_CONTENT"]}\n'
              context_details_str2=context_details_str2+f'Script content: {context["SCRIPT_CONTENT"]}<br/>'
            elif context['EVENT_SIMPLE_NAME']=='NetworkConnectIP4' or context['EVENT_SIMPLE_NAME']=='NetworkReceiveAcceptIP4':
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}{context["LOCAL_ADDRESS_IP4"]}:{context["LOCAL_PORT"]} -> {context["REMOTE_ADDRESS_IP4"]}:{context["REMOTE_PORT"]} (Protocol:{context["PROTOCOL"]})\n'
              context_details_str2=context_details_str2+f'{context["LOCAL_ADDRESS_IP4"]}:{context["LOCAL_PORT"]} -> {context["REMOTE_ADDRESS_IP4"]}:{context["REMOTE_PORT"]} (Protocol:{context["PROTOCOL"]})<br/>'
            elif context['EVENT_SIMPLE_NAME']=='NetworkConnectIP6' or context['EVENT_SIMPLE_NAME']=='NetworkReceiveAcceptIP6':
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}{context["LOCAL_ADDRESS_IP6"]}:{context["LOCAL_PORT"]} -> {context["REMOTE_ADDRESS_IP6"]}:{context["REMOTE_PORT"]} (Protocol:{context["PROTOCOL"]})\n'
              context_details_str2=context_details_str2+f'{context["LOCAL_ADDRESS_IP6"]}:{context["LOCAL_PORT"]} -> {context["REMOTE_ADDRESS_IP6"]}:{context["REMOTE_PORT"]} (Protocol:{context["PROTOCOL"]})<br/>'
            elif context['EVENT_SIMPLE_NAME'] in ('DnsRequest','SuspiciousDnsRequest'):
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}Requested: {context["DOMAIN_NAME"]}\n'
              context_details_str2=context_details_str2+f'Requested: {context["DOMAIN_NAME"]}<br/>'
              context_details_str=context_details_str+f'{indent4}Request type: {context["REQUEST_TYPE"]}\n'
              context_details_str2=context_details_str2+f'Request type: {context["REQUEST_TYPE"]}<br/>'
              # A DNS response could return IPv4 and IPv6 at the same time
              if context["IP4_RECORDS"]!="":
                context_details_str=context_details_str+f'{indent4}Resolved IPv4 addresses: {context["IP4_RECORDS"]}\n'
                context_details_str2=context_details_str2+f'Resolved IPv4 addresses: {context["IP4_RECORDS"]}<br/>'
              if context["IP6_RECORDS"]!="":
                context_details_str=context_details_str+f'{indent4}Resolved IPv6 addresses: {context["IP6_RECORDS"]}\n'
                context_details_str2=context_details_str2+f'Resolved IPv6 addresses: {context["IP6_RECORDS"]}<br/>'
              if context["CNAME_RECORDS"]!="":
                context_details_str=context_details_str+f'{indent4}CNAME Records: {context["CNAME_RECORDS"]}\n'
                context_details_str2=context_details_str2+f'CNAME Records: {context["CNAME_RECORDS"]}<br/>'
              if context["QUERY_STATUS"]!="":
                context_details_str=context_details_str+f'{indent4}Query status: {context["QUERY_STATUS"]}\n'
                context_details_str2=context_details_str2+f'Query status: {context["QUERY_STATUS"]}<br/>'
            elif context['EVENT_SIMPLE_NAME']=='CriticalFileAccessed':
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}File name: {context["TARGET_FILE_NAME"]}\n'
              context_details_str2=context_details_str2+f'File name: {context["TARGET_FILE_NAME"]}<br/>'
            elif context['EVENT_SIMPLE_NAME'] in ('JavaClassFileWritten','GzipFileWritten','DirectoryCreate','ExecutableDeleted'):
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}File name: {context["TARGET_FILE_NAME"]}\n'
              context_details_str2=context_details_str2+f'File name: {context["TARGET_FILE_NAME"]}<br/>'
            elif context['EVENT_SIMPLE_NAME'] in ('OleFileWritten','LnkFileWritten','JpegFileWritten','BmpFileWritten','CabFileWritten','PdfFileWritten','DmpFileWritten','ELFFileWritten','EmailFileWritten','EseFileWritten','GifFileWritten','JarFileWritten','LnkFileWritten','MsiFileWritten','ZipFileWritten','WebScriptFileWritten','TarFileWritten','PngFileWritten'):
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}File name: {context["TARGET_FILE_NAME"]}\n'
              context_details_str2=context_details_str2+f'File name: {context["TARGET_FILE_NAME"]}<br/>'
              tmp=[]
              if "SIZE" in context and context["SIZE"]!="":
                tmp.append(f'File size: {context["SIZE"]} bytes')
              if "IS_ON_REMOVABLE_DISK" in context and context["IS_ON_REMOVABLE_DISK"]!="":
                tmp.append(f'Is on removable disk: {context["IS_ON_REMOVABLE_DISK"]}')
              if "IS_ON_NETWORK" in context and context["IS_ON_NETWORK"]!="":
                tmp.append(f'Is on network: {context["IS_ON_NETWORK"]}')
              if len(tmp)>0:
                context_details_str=context_details_str+f'{indent4}'+(','.join(tmp))+'\n'
                context_details_str2=context_details_str2+(','.join(tmp))+'<br/>'
            elif context['EVENT_SIMPLE_NAME'] in ('FileOpenInfo','RansomwareOpenFile','NewExecutableWritten','NewScriptWritten'):
              if context['EVENT_SIMPLE_NAME']=='FileOpenInfo':
                context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33mFile Opened\033[0m:'
                context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">File Opened</span>:<br/>'
              else:
                context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
                context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}File name: {context["TARGET_FILE_NAME"]}\n'
              context_details_str2=context_details_str2+f'File name: {context["TARGET_FILE_NAME"]}<br/>'
              if "STATUS" in context and context["STATUS"]!="":
                context_details_str=context_details_str+f'{indent4}Status: {context["STATUS"]}\n'
                context_details_str2=context_details_str2+f'Status: {context["STATUS"]}<br/>'
            elif context['EVENT_SIMPLE_NAME']=='NewExecutableRenamed':
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}From :{context["SOURCE_FILE_NAME"]} --To-> {context["TARGET_FILE_NAME"]}\n'
              context_details_str2=context_details_str2+f'From :{context["SOURCE_FILE_NAME"]} --To-> {context["TARGET_FILE_NAME"]}<br/>'
            elif context['EVENT_SIMPLE_NAME']=='CreateService':
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              tmp1=""
              if context["SERVICE_OBJECT_NAME"]!="":
                tmp1=f' Object name: {context["SERVICE_OBJECT_NAME"]} ,'
              context_details_str=context_details_str+f'{indent4}Service name: {context["SERVICE_DISPLAY_NAME"]}, Image path: {context["SERVICE_IMAGE_PATH"]},{tmp1} Start status: {context["SERVICE_START"]}, Service type: {context["SERVICE_TYPE"]}, Error control: {context["SERVICE_ERROR_CONTROL"]}\n'
              context_details_str2=context_details_str2+f'Service name: {context["SERVICE_DISPLAY_NAME"]}, Image path: {context["SERVICE_IMAGE_PATH"]},{tmp1} Start status: {context["SERVICE_START"]}, Service type: {context["SERVICE_TYPE"]}, Error control: {context["SERVICE_ERROR_CONTROL"]}<br/>'
            elif context['EVENT_SIMPLE_NAME']=='ServiceStarted':
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}Service name: {context["SERVICE_DISPLAY_NAME"]}, Image file name: {context["IMAGE_FILE_NAME"]}\n'
              context_details_str2=context_details_str2+f'Service name: {context["SERVICE_DISPLAY_NAME"]}, Image file name: {context["IMAGE_FILE_NAME"]}<br/>'
            elif context['EVENT_SIMPLE_NAME']=='ModifyServiceBinary':
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              tmp1=""
              if context["SERVICE_DESCRIPTION"]!="":
                tmp1=f' Description: {context["SERVICE_DESCRIPTION"]} ,'        
              context_details_str=context_details_str+f'{indent4}Service name: {context["SERVICE_DISPLAY_NAME"]},{tmp1} Image path: {context["SERVICE_IMAGE_PATH"]}, Error control: {context["SERVICE_ERROR_CONTROL"]}\n'
              context_details_str2=context_details_str2+f'Service name: {context["SERVICE_DISPLAY_NAME"]},{tmp1} Image path: {context["SERVICE_IMAGE_PATH"]}, Error control: {context["SERVICE_ERROR_CONTROL"]}<br/>'      
            elif context['EVENT_SIMPLE_NAME']=='HttpRequest':
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}HTTP method: {context["HTTP_METHOD"]}, Hostname: {context["HTTP_HOST"]} ({context["REMOTE_ADDRESS_IP4"]}:{context["REMOTE_PORT"]}), HTTP Path: {context["HTTP_PATH"]}\n'
              context_details_str2=context_details_str2+f'HTTP method: {context["HTTP_METHOD"]}, Hostname: {context["HTTP_HOST"]} ({context["REMOTE_ADDRESS_IP4"]}:{context["REMOTE_PORT"]}), HTTP Path: {context["HTTP_PATH"]}<br/>'
            elif context['EVENT_SIMPLE_NAME']=='CriticalEnvironmentVariableChanged':
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}Variable name: {context["ENVIRONMENT_VARIABLE_NAME"]}, Variable value: {context["ENVIRONMENT_VARIABLE_VALUE"]}\n'
              context_details_str2=context_details_str2+f'Variable name: {context["ENVIRONMENT_VARIABLE_NAME"]}, Variable value: {context["ENVIRONMENT_VARIABLE_VALUE"]}<br/>'
            elif context['EVENT_SIMPLE_NAME'] in ('TerminateProcess','EndOfProcess'):
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}Process terminated\n'
              context_details_str2=context_details_str2+f'Process terminated<br/>'
            elif context['EVENT_SIMPLE_NAME']=="SuspiciousCreateSymbolicLink":
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}Symbolic link name: {context["SYMBOLIC_LINK_NAME"]}, Symbolic link target: {context["SYMBOLIC_LINK_TARGET"]}\n'
              context_details_str2=context_details_str2+f'Symbolic link name: {context["SYMBOLIC_LINK_NAME"]}, Symbolic link target: {context["SYMBOLIC_LINK_TARGET"]}<br/>'
              context_details_str=context_details_str+f'{indent4}Status: {context["STATUS"]}\n'
              context_details_str2=context_details_str2+f'Status: {context["STATUS"]}<br/>'
            elif context['EVENT_SIMPLE_NAME'] in ("InjectedThread","BrowserInjectedThread"):
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}Target process ID: {context["TARGET_PROCESS_ID"]}, Target thread ID: {context["TARGET_THREAD_ID"]}, Injected thead flags: ({context["INJECTED_THREAD_FLAG"]})\n'
              context_details_str2=context_details_str2+f'Target process ID: {context["TARGET_PROCESS_ID"]}, Target thread ID: {context["TARGET_THREAD_ID"]}, Injected thead flags: ({context["INJECTED_THREAD_FLAG"]})<br/>'
              if context["TARGET_PROCESS_ID"]!='' and context["TARGET_PROCESS_ID"] in processes and processes[context["TARGET_PROCESS_ID"]] and processes[context["TARGET_PROCESS_ID"]]['AID']:
                context_details_str=context_details_str+f'{indent4}Associated command line: {context["REG_OBJECT_NAME"]}\n'
                context_details_str2=context_details_str2+f'Associated command line: {context["REG_OBJECT_NAME"]}<br/>'
            elif context['EVENT_SIMPLE_NAME']=="ProcessInjection":
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}Target process ID: {context["TARGET_PROCESS_ID"]}, Target thread ID: {context["TARGET_THREAD_ID"]}, Thread execution control type: {context["THREAD_EXECUTION_CONTROL_TYPE"]}, Well known target function: {context["WELL_KNOWN_TARGET_FUNCTION"]}\n'
              context_details_str2=context_details_str2+f'Target process ID: {context["TARGET_PROCESS_ID"]}, Target thread ID: {context["TARGET_THREAD_ID"]}, Thread execution control type: {context["THREAD_EXECUTION_CONTROL_TYPE"]}, Well known target function: {context["WELL_KNOWN_TARGET_FUNCTION"]}<br/>'
              context_details_str=context_details_str+f'{indent4}Source image path: {context["INJECTOR_IMAGE_FILE_NAME"]}\n'
              context_details_str2=context_details_str2+f'Source image path: {context["INJECTOR_IMAGE_FILE_NAME"]}<br/>'
              context_details_str=context_details_str+f'{indent4}Target image path: {context["INJECTEE_IMAGE_FILE_NAME"]}\n'
              context_details_str2=context_details_str2+f'Target image path: {context["INJECTEE_IMAGE_FILE_NAME"]}<br/>'
              if context["MODULE_NAME"]!='':
                context_details_str=context_details_str+f'{indent4}Module name: {context["MODULE_NAME"]}\n'
                context_details_str2=context_details_str2+f'Module name: {context["MODULE_NAME"]}<br/>'
              if context["EXECUTABLE_BYTES"]!='':
                context_details_str=context_details_str+f'{indent4}Executable bytes: {context["EXECUTABLE_BYTES"]}\n'
                context_details_str2=context_details_str2+f'Executable bytes: {context["EXECUTABLE_BYTES"]}<br/>'
            elif context['EVENT_SIMPLE_NAME']=="AsepValueUpdate":
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}Registry operation type: {context["REG_OPERATION_TYPE"]}\n'
              context_details_str2=context_details_str2+f'Registry operation type: {context["REG_OPERATION_TYPE"]}<br/>'
              context_details_str=context_details_str+f'{indent4}Registry object name: {context["REG_OBJECT_NAME"]}\n'
              context_details_str2=context_details_str2+f'Registry object name: {context["REG_OBJECT_NAME"]}<br/>'
              context_details_str=context_details_str+f'{indent4}Registry type: {context["REG_TYPE"]}\n'
              context_details_str2=context_details_str2+f'Registry type: {context["REG_TYPE"]}<br/>'
              if "REG_STRING_VALUE" in context and context["REG_STRING_VALUE"]!="":
                context_details_str=context_details_str+f'{indent4}Registry string value: {context["REG_STRING_VALUE"]}\n'
                context_details_str2=context_details_str2+f'Registry string value: {context["REG_STRING_VALUE"]}<br/>'
              if "REG_NUMERIC_VALUE" in context and context["REG_NUMERIC_VALUE"]!="":
                context_details_str=context_details_str+f'{indent4}Registry numeric value: {context["REG_NUMERIC_VALUE"]}\n'
                context_details_str2=context_details_str2+f'Registry numeric value: {context["REG_NUMERIC_VALUE"]}<br/>'
              if "REG_BINARY_VALUE" in context and context["REG_BINARY_VALUE"]!="":
                context_details_str=context_details_str+f'{indent4}Registry binary value: {context["REG_BINARY_VALUE"]}\n'
                context_details_str2=context_details_str2+f'Registry binary value: {context["REG_BINARY_VALUE"]}<br/>'
              if "REG_VALUE_NAME" in context and context["REG_VALUE_NAME"]!="":
                context_details_str=context_details_str+f'{indent4}Registry value name: {context["REG_VALUE_NAME"]}\n'
                context_details_str2=context_details_str2+f'Registry value name: {context["REG_VALUE_NAME"]}<br/>'
              context_details_str=context_details_str+f'{indent4}Registry value type: {context["ASEP_VALUE_TYPE"]}, Class: {context["ASEP_CLASS"]}, Flags: {context["ASEP_FLAGS"]}, Index: {context["ASEP_INDEX"]}, Data1: {context["DATA1"]}\n'
              context_details_str2=context_details_str2+f'Registry value type: {context["ASEP_VALUE_TYPE"]}, Class: {context["ASEP_CLASS"]}, Flags: {context["ASEP_FLAGS"]}, Index: {context["ASEP_INDEX"]}, Data1: {context["DATA1"]}<br/>'
              if context["TARGET_FILE_NAME"]!="":
                context_details_str=context_details_str+f'{indent4}Target file: {context["TARGET_FILE_NAME"]} (SHA26: {context["TARGET_SHA256_HASH_DATA"]})\n'
                context_details_str2=context_details_str2+f'Target file: {context["TARGET_FILE_NAME"]} (SHA26: {context["TARGET_SHA256_HASH_DATA"]})<br/>'
            elif context['EVENT_SIMPLE_NAME']=="SuspiciousRegAsepUpdate":
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              context_details_str=context_details_str+f'{indent4}Registry operation type: {context["REG_OPERATION_TYPE"]}\n'
              context_details_str2=context_details_str2+f'Registry operation type: {context["REG_OPERATION_TYPE"]}<br/>'
              context_details_str=context_details_str+f'{indent4}Registry object name: {context["REG_OBJECT_NAME"]}\n'
              context_details_str2=context_details_str2+f'Registry object name: {context["REG_OBJECT_NAME"]}<br/>'
              context_details_str=context_details_str+f'{indent4}Registry type: {context["REG_TYPE"]}\n'
              context_details_str2=context_details_str2+f'Registry type: {context["REG_TYPE"]}<br/>'
              if "REG_STRING_VALUE" in context and context["REG_STRING_VALUE"]!="":
                context_details_str=context_details_str+f'{indent4}Registry string value: {context["REG_STRING_VALUE"]}\n'
                context_details_str2=context_details_str2+f'Registry string value: {context["REG_STRING_VALUE"]}<br/>'
              if "REG_NUMERIC_VALUE" in context and context["REG_NUMERIC_VALUE"]!="":
                if "REG_STRING_VALUE" in context and context["REG_STRING_VALUE"]!="":
                  if context["REG_STRING_VALUE"]!=context["REG_NUMERIC_VALUE"]:
                    context_details_str=context_details_str+f'{indent4}Registry numeric value: {context["REG_NUMERIC_VALUE"]}\n'
                    context_details_str2=context_details_str2+f'Registry numeric value: {context["REG_NUMERIC_VALUE"]}<br/>'
                else:
                  context_details_str=context_details_str+f'{indent4}Registry numeric value: {context["REG_NUMERIC_VALUE"]}\n'
                  context_details_str2=context_details_str2+f'Registry numeric value: {context["REG_NUMERIC_VALUE"]}<br/>'
              if "REG_BINARY_VALUE" in context and context["REG_BINARY_VALUE"]!="":
                context_details_str=context_details_str+f'{indent4}Registry binary value: {context["REG_BINARY_VALUE"]}\n'
                context_details_str2=context_details_str2+f'Registry binary value: {context["REG_BINARY_VALUE"]}<br/>'
              if "REG_VALUE_NAME" in context and context["REG_VALUE_NAME"]!="":
                context_details_str=context_details_str+f'{indent4}Registry value name: {context["REG_VALUE_NAME"]}\n'
                context_details_str2=context_details_str2+f'Registry value name: {context["REG_VALUE_NAME"]}<br/>'
              context_details_str=context_details_str+f'{indent4}Registry config value type: {context["REG_CONFIG_VALUE_TYPE"]}, Class: {context["REG_CONFIG_CLASS"]}, Flags: {context["REG_CONFIG_FLAGS"]}, Index: {context["REG_CONFIG_INDEX"]}\n'
              context_details_str2=context_details_str2+f'Registry config value type: {context["REG_CONFIG_VALUE_TYPE"]}, Class: {context["REG_CONFIG_CLASS"]}, Flags: {context["REG_CONFIG_FLAGS"]}, Index: {context["REG_CONFIG_INDEX"]}<br/>'
              if context["TARGET_FILE_NAME"]!="":
                context_details_str=context_details_str+f'{indent4}Target file: {context["TARGET_FILE_NAME"]} (SHA26: {context["TARGET_SHA256_HASH_DATA"]})\n'
                context_details_str2=context_details_str2+f'Target file: {context["TARGET_FILE_NAME"]} (SHA26: {context["TARGET_SHA256_HASH_DATA"]})<br/>'
            elif context['EVENT_SIMPLE_NAME'] in ('UserLogon','UserLogoff','UserLogonFailed','UserLogonFailed2'):
              context_details_str=context_details_str+f'{indent3}Context (at {context["PROCESS_INSTANT"]})   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
              context_details_str2=context_details_str2+f'Context (at {context["PROCESS_INSTANT"]})   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              indent4=indent3.replace('-->','    ')
              print_single_authentication_detail_result=print_single_authentication_detail(indent4[4:],context,context_header=False,extra_line_break=False)
              context_details_str=context_details_str+f'{indent4}'+print_single_authentication_detail_result["shell"]+'\n'
              context_details_str2=context_details_str2+print_single_authentication_detail_result["html"]+f'<br/>'

            if "MD5" in context and context["MD5"]!='':
              context_details_str=context_details_str+f'{indent4}Hash (MD5): {context["MD5"]}\n'
              context_details_str2=context_details_str2+f'Hash (MD5): {context["MD5"]}<br/>'
            if "SHA1" in context and context["SHA1"]!="0000000000000000000000000000000000000000" and context["SHA1"]!='':
              context_details_str=context_details_str+f'{indent4}Hash (SHA1): {context["SHA1"]}\n'
              context_details_str2=context_details_str2+f'Hash (SHA1): {context["SHA1"]}<br/>'
            if "SHA256" in context and context["SHA256"]!='':
              context_details_str=context_details_str+f'{indent4}Hash (SHA256): {context["SHA256"]}\n'
              context_details_str2=context_details_str2+f'Hash (SHA256): {context["SHA256"]}<br/>'

            if (context["USERNAME"] or context["AUTHENTICATION_ID"] or context["TOKEN_TYPE"] or context["USER_SID"]) and context['EVENT_SIMPLE_NAME'] not in ('UserLogon','UserLogoff','UserLogonFailed','UserLogonFailed2'):
              indent4=indent3.replace('-->','    ')
              tmp=[]
              message=""
              if context["USERNAME"] and context["USERNAME"]!='0':
                message=message+f', Username: {context["USERNAME"]}'
              if context["AUTHENTICATION_ID"] and context["AUTHENTICATION_ID"]!='' and context["AUTHENTICATION_ID"]!='unknown':
                message=message+f', AuthenticationID: {context["AUTHENTICATION_ID"]}'
              if context["USER_SID"] and context["USER_SID"]!='' and context["USER_SID"]!='unknown':
                message=message+f', SID: {context["USER_SID"]}'
              if context["TOKEN_TYPE"] and context["TOKEN_TYPE"]!='' and context["TOKEN_TYPE"]!='unknown':
                message=message+f', Token type: {context["TOKEN_TYPE"]}'
              if len(tmp)>0:
                message=f'{indent4}'+(', '.join(tmp))
            single_process_in_a_tree['context'].append(context_details_str2)
            print(context_details_str,end='')

        for child_id in process_details['Children']:
          single_process_in_a_tree['children'].append(print_process_tree(child_id, indent.replace('-->','    ') + '-->'))
          single_edge_in_a_graph={
            "source":str(process_id), 
            "target": str(child_id), 
            "color": "blue", 
            "weight": "1.0",
            "doc-subject": ""
          }
          json_graph["edges"].append(single_edge_in_a_graph)
        single_process_in_a_graph["attributes"]["details"]=single_process_printed
        json_graph["nodes"].append(single_process_in_a_graph)
        single_process_in_a_tree["details"]=single_process_printed
    return single_process_in_a_tree

# Function authentication details
def print_authentication_details(authentication):
        #print(authentication)
        if len(authentication["Context"])>0:
          for context in authentication["Context"]:
            if context['EVENT_SIMPLE_NAME'] in ('UserLogon','UserLogoff','UserLogonFailed','UserLogonFailed2'):
              print(print_single_authentication_detail('',context,context_header=True,extra_line_break=True)["shell"])


def print_single_authentication_detail(indent,context,context_header=False,extra_line_break=False):
              indent2='    '
              context_details_str=f'{indent}Context'
              context_details_str2=f'Context'
              message=f''
              if context["CONTEXT_ID"] and context["CONTEXT_ID"]!='0':
                message=message+f' (ID: {context["CONTEXT_ID"]})'
              if context["LOGON_TIME"] and context["LOGON_TIME"]!='0':
                message=message+f' (Logon time: {context["LOGON_TIME"]})'
              if context["LOGOFF_TIME"] and context["LOGOFF_TIME"]!='0':
                message=message+f' (Logoff time: {context["LOGOFF_TIME"]})'
              if context_header:
                if (context["LOGON_TIME"] and context["LOGON_TIME"]!='0') or (context["LOGOFF_TIME"] and context["LOGOFF_TIME"]!='0'):
                  None
                else:
                  message=message+f' (at {context["PROCESS_INSTANT"]})'
                #message=message+f'   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:'
                #print(message)
                context_details_str=context_details_str+message+f'   \033[33m{context["EVENT_SIMPLE_NAME"]}\033[0m:\n'
                context_details_str2=context_details_str2+message+f'   <span style="color:#fd8d3c">{context["EVENT_SIMPLE_NAME"]}</span>:<br/>'
              message=f'Username: {context["USERNAME"]}'
              if context["USER_PRINCIPAL"] and context["USERNAME"]!=context["USER_PRINCIPAL"]:
                message=message+f' (UPN: {context["USER_PRINCIPAL"]})'
              if context["LOGON_DOMAIN"] and context["LOGON_DOMAIN"]!='-':
                message=message+f' (Logon domain: {context["LOGON_DOMAIN"]})'
              if context["LOGON_TYPE"]:
                message=message+f', Logon Type: {context["LOGON_TYPE"]}'
              if context["LOGON_FLAGS"]:
                message=message+f', Logon flags: {context["LOGON_FLAGS"]}'
              if context["AUTHENTICATION_ID"]:
                message=message+f', AuthenticationID: {context["AUTHENTICATION_ID"]}'
              if context["AUTHENTICATION_PACKAGE"]:
                message=message+f', Authentication Package: {context["AUTHENTICATION_PACKAGE"]}'
              if context["TOKEN_TYPE"]:
                message=message+f', Token type: {context["TOKEN_TYPE"]}'
              if context["REMOTE_ACCOUNT"]:
                message=message+f', Remote account: {context["REMOTE_ACCOUNT"]}'
              if context["USER_SID"]:
                message=message+f', SID: {context["USER_SID"]}'
              context_details_str=context_details_str+indent+indent2+message+f'\n'
              context_details_str2=context_details_str2+message+f'<br/>'
              #print(message)
              message=f''
              if context["REMOTE_ADDRESS_IP4"]:
                message=message+f'Source IP: {context["REMOTE_ADDRESS_IP4"]}'
              elif context["REMOTE_ADDRESS_IP6"]:
                message=message+f'Source IP: {context["REMOTE_ADDRESS_IP6"]}'
              if context["CLIENT_COMPUTER_NAME"] and context["CLIENT_COMPUTER_NAME"]!="-":
                if message==f'':
                  message=message+f'Source Hostname: {context["CLIENT_COMPUTER_NAME"]}'
                else:
                  message=message+f', Source Hostname: {context["CLIENT_COMPUTER_NAME"]}'
              if message==f'':
                None
              else:
                context_details_str=context_details_str+indent+indent2+message+f'\n'
                context_details_str2=context_details_str2+message+f'<br/>'
                #print(message)
              message=f''
              if context["USERISADMIN"]:
                message=message+f'Is local admin: {context["USERISADMIN"]}'
              if context["PASSWORD_LAST_SET"] and context["PASSWORD_LAST_SET"]!='0':
                if message==f'':
                  message=message+f'Password Last Set: {context["PASSWORD_LAST_SET"]}'
                else:
                  message=message+f', Password Last Set: {context["PASSWORD_LAST_SET"]}'
              if message==f'':
                None
              else:
                context_details_str=context_details_str+indent+indent2+message+f'\n'
                context_details_str2=context_details_str2+message+f'<br/>'
                #print(message)
              if context["STATUS"] or context["SUBSTATUS"]:
                #message=f''
                context_details_str=context_details_str+f'{indent}{indent2}Status: {context["STATUS"]}.\n'
                context_details_str2=context_details_str2+f'Status: {context["STATUS"]}.<br/>'
                #print(message)
                #message=f''
                context_details_str=context_details_str+f'{indent}{indent2}Sub-status: {context["SUBSTATUS"]}.\n'
                context_details_str2=context_details_str2+f'Sub-status: {context["SUBSTATUS"]}.<br/>'
                #print(message)
              if extra_line_break:
                context_details_str=context_details_str+f'\n'
                context_details_str2=context_details_str2+f'<br/>'
                #print()
              return {"shell":context_details_str,"html":context_details_str2}

#print(root_process_ids)
# Starting from the root process, print the process tree
root_process_id = 0  # Set the root process ID here
for aid in all_aid:
  i=1
  for root_process_id in root_process_ids:
    if processes[root_process_id]['AID']==aid:
      if i==1:
        print("\n\n\n------------Agent ID: "+aid+"-----------")
        if aid in authentications:
          print("\nAuthentications:")
          print_authentication_details(authentications[aid])
      print("\nProcess Tree N°"+str(i)+":")
      single_process_in_a_tree={
          "name": "Process Tree N°"+str(i)+":",
          "id": i,
          "details": "",
          "context": [],
          "children": []
      }
      print(f'>Parent Process (ID:{root_process_id}):')
      for process_id,process in processes.items():
        #if '70074305948127'==process_id:
        #  print(process)
        #  exit()
        #print(process)
        #print(process['PARENT_PROCESS_ID'],root_process_id)
        #print('PARENT_PROCESS_ID' in process)
        #print(process['EVENT_SIMPLE_NAME'])

        # This part is now obsolete since the parent process now has its default details
        ##print("pid:",process_id,"root:",root_process_id)
        #if 'PARENT_PROCESS_ID' in process and process['PARENT_PROCESS_ID']==root_process_id and process['COMMAND_LINE']!='falcon-sensor':
        #  print_process_tree(process_id,'-->')
        # The process have only the context without having any parent process
        if 'EVENT_SIMPLE_NAME' in process and process['EVENT_SIMPLE_NAME']=='PotentialProcessRollup2' and process_id==root_process_id:
          #print("four")
          single_process_in_a_tree["children"].append(print_process_tree(process_id,'-->'))
      json_tree["children"].append(single_process_in_a_tree)
      i=i+1

print("\n\n\nBulk Processes List to be used in Snowflake to get additional parent and children processes:")
print("('"+("','".join(all_ids))+"')")
#print(json.dumps(json_tree))
relationship=[]
def getRelationship(tree):
  for e in tree["children"]:
    relationship.append(
      {
        "source": tree["id"],
        "target": e["id"],
        "type": "child"
      }
    )
    if len(e["children"])>0:
      getRelationship(e)

getRelationship(json_tree)
#print(relationship)
#print(json.dumps(json_graph))

# Writing to sample.json
with open(home+"/Documents/EDR-Process-Explorer/web/flare.json", "w") as outfile:
    outfile.write(json.dumps(json_tree))


