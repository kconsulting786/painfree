# Painfree results (private)

Scan results uploaded by `painfree.ps1 -Upload`. Each scan lands in `results/<COMPUTER>/<yyyy-MM-dd_HHmm>/` as `report.json` and `report.html`.

A daily GitHub Action deletes scans older than 3 days and squashes the history, so old results are not kept in git either. Keep this repository private.
