# Splunk + BOTS v3 setup

Local Splunk instance for working the BOTS v3 investigation dataset. Runs in Docker. On Apple Silicon the Splunk image runs as amd64 under emulation, so first boot is slow (a few minutes).

## Prerequisites

- Docker Desktop installed and running
- About 3 GB free disk for the dataset and container

## Steps

1. Download and extract the dataset (about 320 MB) into `datasets/`:

   ```bash
   mkdir -p datasets && cd datasets
   curl -L -o botsv3_data_set.tgz https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz
   md5 botsv3_data_set.tgz   # expect: d7ccca99a01cff070dff3c139cdc10eb
   tar -xvzf botsv3_data_set.tgz
   cd ..
   ```

   This extracts to `datasets/botsv3_data_set/`. The `datasets/` folder is gitignored.

2. Start Splunk. The compose file uses named volumes, no bind mount, so boot does not fail on the dataset's read-only files:

   ```bash
   docker compose up -d
   docker compose logs -f   # wait for "Ansible playbook complete", then Ctrl+C
   ```

3. Copy the dataset app into the container. The folder name must be `botsv3_data_set`, because the dataset's `indexes.conf` hardcodes that path (`$SPLUNK_HOME/etc/apps/botsv3_data_set/...`):

   ```bash
   docker cp ./datasets/botsv3_data_set splunk:/opt/splunk/etc/apps/botsv3_data_set
   ```

4. Fix ownership. This is the step that actually makes the data load. `docker cp` writes the files as root with `0700` permissions, so the Splunk process (uid `41812`) cannot read the index config or the buckets, and every search returns 0 events. Chown the app to the Splunk uid, then restart:

   ```bash
   docker exec -u root splunk chown -R 41812:41812 /opt/splunk/etc/apps/botsv3_data_set
   docker restart splunk
   ```

5. Wait 1 to 2 minutes for the restart. Verify the index config loaded. Run btool as the Splunk uid, not the default exec user, or it cannot write its own log and fails:

   ```bash
   docker exec -u 41812 splunk /opt/splunk/bin/splunk btool indexes list botsv3
   ```

   A `[botsv3]` stanza means the config is loaded.

6. Open http://localhost:8000 (login `admin` / `Changeme123!`), go to Search & Reporting, set the time range to **All time**, and run:

   ```
   index=botsv3 | stats count by sourcetype
   ```

   About 107 sourcetypes totalling ~1.9M events means the data loaded.

## Troubleshooting

- **Search returns 0 events but the index exists.** Almost always ownership. Run `docker exec -u 41812 splunk ls /opt/splunk/etc/apps/botsv3_data_set/var/lib/splunk/botsv3/db`. If it says "Permission denied", redo step 4.
- **`btool` prints "Permission denied" creating `/opt/splunk/var/log/...`.** It ran as the wrong user. Add `-u 41812`.
- **Two `botsv3*` apps exist** (e.g. a leftover `botsv3` from an earlier wrong-named copy). Remove the wrong one inside the container, then restart: `docker exec -u root splunk rm -rf /opt/splunk/etc/apps/botsv3`. A stale app with a broken `props.conf` also shows up as parse warnings in `splunkd.log`.

## Notes

- Set the time picker to All time. BOTS v3 data is from 2018, so any recent-time range returns nothing.
- The dataset was built on Splunk 7.1.7. Version 9.4.3 reads it.
- Stop with `docker compose down`. Named volumes keep Splunk config and the imported app across restarts.
