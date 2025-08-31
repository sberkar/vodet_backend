from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from multiprocessing import Process
import os
from pcap_data_processing import process_pcap_for_model as pca
import uuid
import pandas as pd
from flask_cors import CORS
from classification import classify_helper, classifier_model

app = Flask(__name__)
CORS(app)  # This enables CORS for all routes and origins by default



@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error":"No file part"}), 400

    accepted_extensions = ('pcap', 'pcapng', 'log', 'arff')

    file = request.files['file']
    filename = secure_filename(file.filename)
    if filename == '':
        return jsonify({"error":"No selected file"}), 400
    if not filename.lower().endswith(accepted_extensions):
        return jsonify({"error":"Unsupported file type"}), 400
    get_file_type = filename.split('.')[-1].lower()

    save_path = os.path.join('uploads', filename)
    os.makedirs('uploads', exist_ok=True)
    file.save(save_path)

    if get_file_type in ('pcap', 'pcapng'):
        jobid = str(uuid.uuid4())
        output_csv = os.path.join('processed', f"{jobid}_processed.csv")
        os.makedirs('processed', exist_ok=True)
        jobfile = os.path.join('jobs', f"{jobid}_job.json")
        os.makedirs('jobs', exist_ok=True)

        process = Process(target=pca, args=(save_path, output_csv, jobid))
        process.start()

        status = 1

        open(jobfile, 'w').write(f'{{"job_id": "{jobid}", "status": "{status}", "output": "{jobid}_processed.csv"}}')

        return jsonify({"message": f"File uploaded and processing started. Output will be saved to {output_csv}", "status":status, "jobid": jobid}), 202
    else:
        return jsonify({"error":"Currently only pcap and pcapng files are supported for processing"}), 400

@app.route('/job_status/<jobid>', methods=['GET'])
def job_status(jobid):
    if not jobid:
        return jsonify({"error":"Job ID is required"}), 400
    jobfile = open(os.path.join('jobs', f"{jobid}_job.json"), 'r')
    if not jobfile:
        return jsonify({"error":"Job ID not found"}), 404
    status_info = eval(jobfile.read())
    jobfile.close()
    return jsonify({"job_status": status_info}), 200

@app.route('/classify/<jobid>', methods=['POST'])
def classify(jobid):
    jobfile_path = os.path.join('jobs', f"{jobid}_job.json")
    if not os.path.exists(jobfile_path):
        return jsonify({"error":"Job ID not found"}), 404
    jobfile = open(jobfile_path, 'r')
    job_info = eval(jobfile.read())
    jobfile.close()
    if job_info['status'] != 0:
        return jsonify({"error":"Job processing is not completed yet"}), 400
    output_csv_file = job_info['output']
    output_csv = os.path.join('processed', output_csv_file)
    if not os.path.exists(output_csv):
        return jsonify({"error":"Processed file not found"}), 404
    try:
        if not classifier_model:
            return jsonify({"error":"Failed to load model"}), 500
        
        process = Process(target=classify_helper, args=(jobid, output_csv))
        process.start()

        return {
            "message": "Classification started.",
            "status": 3
        }, 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        pass

@app.route('/results/<result_id>', methods=['GET'])
def results(result_id):
    result_csv = os.path.join('results', f"{result_id}.csv")
    if not os.path.exists(result_csv):
        return jsonify({"error": "Result not found"}), 404
    data = pd.read_csv(result_csv)
    # pagination logic
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 25, type=int)

    data_paginated = data.iloc[(page - 1) * per_page:page * per_page]
    return jsonify({"results": data_paginated.to_dict(orient='records')}), 200

if __name__ == '__main__':
    app.run(debug=True)