import requests
import tomllib
import os


url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
headers = {
    'accept': 'application/json'

}

mitreData = requests.get(url, headers=headers).json()
mitreMapped = {}
failure = 0

#print(mitreData)

#def getMapping(mitreData):


# for x in mitreData:
#     print(x)

# for object in mitreData['objects']:
#     print(object)

for object in mitreData['objects']:
    tactics = []
    if object['type'] == 'attack-pattern':
        #print(object)
        if 'external_references' in object:
            for reference in object['external_references']:
                #print(reference)
                if 'external_id' in reference:
                    if ((reference['external_id'].startswith("T"))):
                    #print(reference)
                        if 'kill_chain_phases' in object:
                                #print(object['kill_chain_phases'])
                                for tactic in object['kill_chain_phases']:
                                     #print(tactic)
                                     tactics.append(tactic['phase_name'])
                        technique = reference['external_id']
                        name = object['name']
                        url = reference['url']
                        #print(technique + " : " + name + " : " + url)
                        #print(technique + " : " + str(tactics))

                        if 'x_mitre_deprecated' in object:
                             deprecated = object['x_mitre_deprecated']
                             #print(object['name'] + " : " + str(deprecated))
                             filtered_object = {'tactics': str(tactics), 'technique': technique, 'name': name, 'url': url, 'deprecated': deprecated }
                             mitreMapped[technique] = filtered_object
                             #print(filtered_object)
                        else:
                             filtered_object = {'tactics': str(tactics), 'technique': technique, 'name': name, 'url': url, 'deprecated': "False" }
                             mitreMapped[technique] = filtered_object

#print(mitreMapped)
#print(mitreMapped['T1123']['name'])
#print(mitreMapped['T1123']['url'])
#print(mitreMapped['T1123']['deprecated'])                           
alert_data = {}

#for root, dirs, files in os.walk("C:\Scripts\Python\custom_alerts"):
for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
            #print(file)
            full_path = os.path.join(root, file)
            #print(full_path)
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)
                filtered_object_array = []
                #print(alert)
                if alert['rule']['threat'][0]['framework'] == "MITRE ATT&CK":
                     for threat in alert['rule']['threat']:
                         technique_id = threat['technique'][0]['id']
                         technique_name =  threat['technique'][0]['name']

                         if 'tactic' in threat:
                            tactic = threat['tactic']['name']
                         else:
                            tactic = "none"
                         if 'subtechnique' in threat['technique'][0]:
                             #print(threat)
                             subtechnique_id = threat['technique'][0]['subtechnique'][0]['id']
                             subtechnique_name = threat['technique'][0]['subtechnique'][0]['name']
                         else:
                             subtechnique_id = "none"
                             subtechnique_name = "none"

                         
                         #print(file + " : " + tactic + " : " + technique_id + " : " + technique_name + " : " + subtechnique_id + " : " + subtechnique_name)
                         #print(file + " : " + tactic + " : " + technique_id + " : " + technique_name)

                         filtered_object = {'tactic': tactic, 'technique_id': technique_id, 'technique_name': technique_name, 'subtechnique_id': subtechnique_id, 'subtechnique_name': subtechnique_name}
                         filtered_object_array.append(filtered_object)
                         alert_data[file] = filtered_object_array
mitre_tactic_list = ['none','Reconnaissance','Resource Development','Initial Access','Execution','Persistence','Privilege Escalation','Defense Evasion','Credential Access','Discovery','Lateral Movement','Collection','Command and Control','Exfiltration','Impact']

#print(alert_data)
for file in alert_data:
    for line in alert_data[file]:
        #print(line)
        tactic=line['tactic']
        technique_id=line['technique_id']
        subtechnique_id=line['subtechnique_id'] 
        #print(file + " : " + tactic + " : " + technique_id + " : " + subtechnique_id)                        

        # Check to ensure MITRE Tactics exist
        if tactic not in mitre_tactic_list:
            print("The MITRE Tactic supplied does not exist: " + "\"" + tactic + "\"" + " in " + file)
            failure = 1

        # Check to make sure the MITRE Technique ID is valid
        try:
            if mitreMapped[technique_id]:
                pass
        except KeyError:
            print("Invalid MITRE Technique ID: " + "\"" + technique_id + "\"" + " in " + file)
            failure = 1

        # Check to see if the MITRE TID + Name combination is valid
        try:
            mitre_name = mitreMapped[technique_id]['name']
            alert_name = line['technique_name']
            if alert_name != mitre_name:
                print("MITRE Technique ID and Name Mismatch in " + file + " EXPECTED: " + "\"" + mitre_name + "\"" + " GIVEN: " + "\"" + alert_name + "\"")
                failure = 1
        except KeyError:
            pass
        # Check to see if the SubTID + Name Entry is valid
        try:
            if subtechnique_id != "none":
                mitre_name = mitreMapped[subtechnique_id]['name']
                alert_name = line['subtechnique_name']
            if alert_name != mitre_name:
                print("MITRE Sub-Technique ID and Name Mismatch in " + file + " EXPECTED: " + "\"" + mitre_name + "\"" + " GIVEN: " + "\"" + alert_name + "\"")
                failure = 1
        except KeyError:
            pass

        # Check to see if the technique is deprecated
        try:
            if mitreMapped[technique_id]['deprecated'] == True:
                print("Deprecated MITRE Technique ID: " + "\"" + technique_id + "\"" + " in " + file)
                failure = 1 
        except KeyError:
            pass

if failure != 0:
    sys.exit(1)
                        
                         
                             

                     