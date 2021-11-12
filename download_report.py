
from google.cloud import storage


service_account_json = 'service_account.json'

cloud_storage_bucket_name = 'pubsite_prod_8425839137660839956'

destination_file_name = 'report.csv'

# source_blob_repot_name = reviews/reviews_[package_name]_YYYYMM.csv
# can find it from "Download Report" button url on
# https://play.google.com/console/u/1/developers/8425839137660839956/download-reports/statistics?appId=4975612701246292012
source_blob_repot_name = 'stats/installs/installs_net.webike.app01_202109_country.csv'

def download_blob_report():
  
  # Explicitly use service account credentials by specifying the private key file.
  storage_client = storage.Client.from_service_account_json(service_account_json)
  
  bucket = storage_client.bucket(cloud_storage_bucket_name)
  
  blob = bucket.blob(source_blob_repot_name)
  
  blob.download_to_filename(destination_file_name)

  print(
      "Blob {} downloaded to {}.".format(
          source_blob_repot_name, destination_file_name
      )
  )

download_blob_report()
