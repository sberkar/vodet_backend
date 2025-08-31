import xgboost as xgb
import pandas as pd
import os

classifier_model = xgb.XGBClassifier()
model_path = 'ai_model/voip_classifier_model_pcap.json'
classifier_model.load_model(model_path)

def classify_helper(jobid, output_csv):
    jobfile_path = os.path.join('jobs', f"{jobid}_job.json")

    if not os.path.exists(jobfile_path):
        raise FileNotFoundError("Job ID not found")

    with open(jobfile_path, 'w') as jobfile:
        jobfile.write(f'{{"job_id": "{jobid}", "status": 3, "output": "{os.path.basename(output_csv)}"}}')

    data = pd.read_csv(output_csv)

        
    data['protocol_udp'] = data['protocol'].apply(lambda x: 1 if x == 'UDP' else 0)

    features = data.drop(columns=['src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port'])
    predictions = classifier_model.predict(features)
    data['is_voip'] = predictions

    result_csv = os.path.join('results', f"{os.path.splitext(os.path.basename(output_csv))[0]}_results.csv")
    os.makedirs('results', exist_ok=True)
    data.to_csv(result_csv, index=False)

    with open(jobfile_path, 'w') as jobfile:
        jobfile.write(f'{{"job_id": "{jobid}", "status": 1, "output": "{os.path.basename(result_csv)}"}}')
