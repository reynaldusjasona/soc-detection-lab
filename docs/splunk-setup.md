# Splunk + BOTS v3 setup

Local Splunk instance for working the BOTS v3 investigation dataset. Runs in Docker. On Apple Silicon the Splunk image runs as amd64 under emulation, so first boot is slow (a few minutes).

## Prerequisites

- Docker Desktop installed and running
- About 3 GB free disk for the dataset and container

## Steps

1. Download the dataset (about 320 MB) into `datasets/`:

   ```bash
   mkdir -p datasets && cd datasets
   curl -L -o botsv3_data_set.tgz https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz
   md5 botsv3_data_set.tgz   # expect: d7ccca99a01cff070dff3c139cdc10eb
   tar -xvzf botsv3_data_set.tgz
   cd ..
   ```

   This extracts to `datasets/botsv3_data_set/`. The `datasets/` folder is gitignored.

2. Start Splunk clean (the compose file uses named volumes, no bind mount, so provisioning does not fail on read-only files):

   ```bash
   docker compose up -d
   docker compose logs -f   # wait for "Ansible playbook complete", then Ctrl+C
   ```

3. Copy the dataset app into Splunk. The folder name must be `botsv3_data_set`, because the dataset's `indexes.conf` hardcodes that path (`$SPLUNK_HOME/etc/apps/botsv3_data_set/...`). A different name means Splunk cannot find the index data.

   ```bash
   docker cp ./datasets/botsv3_data_set splunk:/opt/splunk/etc/apps/botsv3_data_set
   docker exec -u root splunk chown -R splunk:splunk /opt/splunk/etc/apps/botsv3_data_set
   docker restart splunk
   ```

4. Wait 1 to 2 minutes for the restart, then open http://localhost:8000 (login `admin` / `Changeme123!`), go to Search & Reporting, set the time range to **All time**, and run:

   ```
   index=botsv3 | stats count by sourcetype
   ```

   A table of sourcetypes with counts means the data loaded.

## Notes

- Set the time picker to All time. BOTS v3 data is from 2018, so any recent-time range returns nothing.
- The dataset was built on Splunk 7.1.7. Version 9.4.3 reads it.
- Stop with `docker compose down`. Named volumes keep Splunk config and the imported app across restarts.
