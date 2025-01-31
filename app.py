from flask import Flask, render_template
import requests
from pymongo import MongoClient, UpdateOne
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime

app = Flask(__name__)

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")  # Change this if needed
db = client["cve_database"]
cve_collection = db["cve_data"]

# NVD API Base URL
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 200  # Max limit per request

# Helper function to validate and clean date fields (only return date without time)
def clean_date(date_str):
    try:
        # Extract only the date in 'YYYY-MM-DD' format (without time)
        return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f").date().isoformat()
    except (ValueError, TypeError):
        return "Unknown"

# Function to fetch CVEs based on modified date
def fetch_and_store_cves(last_modified_date=None):
    start_index = 0
    total_results = None
    bulk_updates = []
    seen_cve_ids = set()  # To track duplicate CVE IDs
    
    params = {
        "startIndex": start_index,
        "resultsPerPage": RESULTS_PER_PAGE
    }

    if last_modified_date:
        # Fetch data modified after the provided date
        params["modifiedSince"] = last_modified_date

    while total_results is None or start_index < total_results:
        response = requests.get(NVD_API_URL, params=params)
        if response.status_code == 200:
            data = response.json()
            
            if total_results is None:
                total_results = data.get("totalResults", 0)
            
            if "vulnerabilities" in data:
                for item in data["vulnerabilities"]:
                    cve_data = item.get("cve", {})
                    cve_id = cve_data.get("id", "").strip()
                    
                    if not cve_id or cve_id in seen_cve_ids:
                        continue
                    
                    seen_cve_ids.add(cve_id)
                    
                    # Cleanse and extract fields
                    source_identifier = cve_data.get("sourceIdentifier", "Unknown").strip()
                    published = clean_date(cve_data.get("published", "Unknown"))
                    last_modified = clean_date(cve_data.get("lastModified", "Unknown"))
                    status = cve_data.get("vulnStatus", "Unknown").strip()

                    clean_data = {
                        "cve_id": cve_id,
                        "source_identifier": source_identifier,
                        "published": published,
                        "last_modified": last_modified,
                        "status": status
                    }
                    
                    # Upsert operation to prevent duplicates
                    bulk_updates.append(
                        UpdateOne({"cve_id": cve_id}, {"$set": clean_data}, upsert=True)
                    )
                
                if bulk_updates:
                    cve_collection.bulk_write(bulk_updates)
                    print(f"Updated {len(bulk_updates)} CVEs from index {start_index}")
                    bulk_updates.clear()
                
            start_index += RESULTS_PER_PAGE
        else:
            print("Error fetching data from NVD API")
            break

# Function to get the last modified date from the most recent document
def get_last_modified_date():
    last_cve = cve_collection.find_one({}, sort=[("last_modified", -1)])
    return last_cve["last_modified"] if last_cve else None

# Scheduler to sync CVE data periodically (both full and incremental refresh options)
def schedule_cve_sync():
    scheduler = BackgroundScheduler()

    # Choose full refresh or incremental update here
    scheduler.add_job(fetch_and_store_cves, 'interval', hours=6)  # Incremental update every 6 hours

    # Full refresh, fetch all CVEs every 24 hours
    scheduler.add_job(lambda: fetch_and_store_cves(last_modified_date=None), 'interval', hours=24)  # Full refresh every 24 hours
    scheduler.start()

@app.route("/fetch_cves", methods=["GET"])
def fetch_cves():
    # Perform a full refresh or incremental refresh based on your choice
    last_modified_date = get_last_modified_date()  # Get last modified date from DB
    fetch_and_store_cves(last_modified_date)
    return {"message": "CVE data fetched and stored successfully."}

@app.route("/cves/list")
def get_cves():
    cves = list(cve_collection.find({}, {"_id": 0}))  # Get all documents, excluding _id
    # Flatten the 'cve' field for each record
    for cve in cves:
        cve_data = cve.get('cve', {})
        cve['cve_id'] = cve_data.get('id', 'Unknown')
        cve['source_identifier'] = cve_data.get('sourceIdentifier', 'Unknown')
        cve['published'] = cve_data.get('published', 'Unknown')
        cve['last_modified'] = cve_data.get('lastModified', 'Unknown')
        cve['status'] = cve_data.get('vulnStatus', 'Unknown')

        # Clean dates before displaying
        cve['published'] = clean_date(cve['published'])
        cve['last_modified'] = clean_date(cve['last_modified'])
        
    total_records = len(cves)
    return render_template("index.html", cves=cves, total_records=total_records)

if __name__ == "__main__":
    schedule_cve_sync()  # Start the scheduler
    app.run(debug=True)
