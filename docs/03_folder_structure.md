# Folder Structure

## Repository Tree

```text
Network/
├── flows.db
├── passive_timeline.db
├── temp_uploads/
├── nal/
│   ├── backend/
│   │   ├── Dockerfile
│   │   └── app/
│   │       ├── main.py
│   │       ├── db.py
│   │       ├── classification_config.py
│   │       ├── osint_routes.py
│   │       └── services/
│   │           ├── decision_service.py
│   │           ├── realtime_service.py
│   │           ├── osint.py
│   │           ├── threat_feeds.py
│   │           └── sbom_service.py
│   │   └── workers/
│   ├── core/
│   │   └── feature_engineering.py
│   ├── frontend/
│   │   ├── Dockerfile
│   │   ├── package.json
│   │   ├── src/
│   │   │   ├── App.jsx
│   │   │   ├── services/api.js
│   │   │   ├── components/Layout.jsx
│   │   │   └── pages/
│   │   ├── dist/
│   │   └── node_modules/
│   ├── n8n/
│   │   ├── 1_network_security_monitoring.json
│   │   ├── 2_automated_file_analysis.json
│   │   ├── 3_training_pipeline.json
│   │   ├── 4_daily_security_report.json
│   │   ├── 5_live_monitoring_management.json
│   │   ├── import_workflows.sh
│   │   └── README.md
│   ├── training_pipeline/
│   │   ├── train.py
│   │   ├── configs/system_config.template.yaml
│   │   ├── scripts/
│   │   │   ├── generate_synthetic_data.py
│   │   │   ├── generate_doomsday_flows.py
│   │   │   ├── pcap_chunks_to_flows.py
│   │   │   └── setup_project.py
│   │   ├── data/
│   │   │   ├── raw/
│   │   │   └── processed/
│   │   └── models/
│   │       ├── supervised/
│   │       ├── unsupervised/
│   │       ├── artifacts/
│   │       └── metrics.json
│   ├── security/
│   │   └── sbom.json
│   ├── docs/
│   ├── results/
│   ├── temp_processing/
│   ├── tests/
│   ├── requirements.txt
│   ├── docker-compose.yml
│   ├── .env.example
│   └── test_upload.sh
```

## Directory Purpose Notes

- `Network/flows.db`: runtime SQLite store for all flow and analysis metadata used by backend/frontend.
- `Network/passive_timeline.db`: dedicated timeline store for passive dashboard trend bars.
- `Network/temp_uploads`: transient upload staging path used during API processing.
- `nal/backend`: API layer and orchestration logic.
- `nal/core`: shared preprocessing utilities consumed in both training and inference.
- `nal/frontend`: operator UI, charts, and workflow controls.
- `nal/n8n`: automation definitions and import utility.
- `nal/training_pipeline`: training orchestration, dataset tooling, and model artifact generation.
- `nal/security/sbom.json`: existing CycloneDX-style SBOM artifact in repository.
- `nal/docs`: project documentation.

## Important Large/Generated Areas

- `nal/frontend/node_modules` and `nal/frontend/dist` are generated/dependency artifacts.
- `nal/training_pipeline/data/processed` contains many CSV flow slices (large dataset volume).
- `nal/training_pipeline/models` stores generated model artifacts and training metadata.
