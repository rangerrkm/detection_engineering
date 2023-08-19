import tomllib
import sys
import os

#file = "alert_example.toml"
#with open(file,"rb") as toml:
#    alert = tomllib.load(toml)

#for root, dirs, files in os.walk("C:\Scripts\Python\custom_alerts"):
for root, dirs, files in os.walk("C:\Scripts\Python\converted_detections"):
    for file in files:
        if file.endswith(".toml"):
            #print(file)
            full_path = os.path.join(root, file)
            #print(full_path)
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)
                #print(alert)
                present_fields = []
                missing_fields = []

                if alert['rule']['type'] == "query": # query based alert
                    required_fields = ['description','name', 'rule_id', 'risk_score','severity','type','query']
                elif alert['rule']['type'] == "eql": # event correlation alert
                    required_fields = ['description','name', 'rule_id', 'risk_score','severity','type','query', 'language']
                elif alert['rule']['type'] == "threshold": # threshold based alert
                    required_fields = ['description','name', 'rule_id', 'risk_score','severity','type','query', 'threshold']    
                else:
                    print("Unsupported rule type found in: " + full_path)
                    break

                for table in alert:
                    #print(table)
                    for field in alert[table]:
                        present_fields.append(field)
                        #print(present_fields)

                for field in required_fields:
                    if field not in present_fields:
                        missing_fields.append(field)

                # print(required_fields)
                # print("\n")
                # print(present_fields)
                # print("\n")
                # print(missing_fields)

                if missing_fields:
                    print("The following fields do not exist in " + file + ": " + str(missing_fields))
                else:
                    print("Validation Passed for: " + file)

                #print(alert)
                # for table in alert:
                #     #print(table)
                #     for field in alert[table]:
                #         print(field)

                # for field in alert['rule']:
                #     print(field)
                 




