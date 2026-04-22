# Anomaly_IDS


## Start

Set up environment by

```bash
./setup_all.sh
```

## Dependencies

- Docker (`sudo apt install -y ca-certificates curl gnupg lsb-release` , `curl -fsSL https://get.docker.com | sudo sh` , `sudo usermod -aG docker $USER`, `newgrp docker` finally restart your host to apply changes) 
- Docker Compose v2 (`sudo apt install -y docker-compose-plugin`) 
- Python 3 (`sudo apt install -y python3 python3-venv python3-pip`) 
- unzip (`sudo apt install -y unzip`)
- bash (`sudo apt install -y bash`) 
- GNU coreutils (`sudo apt install -y coreutils`) 
- Linux host with systemd-compatible Docker setup 
- Internet access

## Project Structure

```
├── infrastructure/
│   ├── cicflowmeter    # CICFlowMeter (cloned from https://github.com/GintsEngelen/CICFlowMeter)
│   ├── iris-web/       # DFIR-IRIS (cloned from https://github.com/dfir-iris/iris-web.git)
│   ├── docker-compose.yml
│   ├── setup.sh
│   └── teardown.sh
├── model/              # Anomaly Detector
├── data/               # Data Manipulation and Model Testing
├── logs/
├── shared/
├── src/
├── requirements.txt    # Python Dependencies
└── setup_all.sh
```

## Network

```
Network: 10.0.0.0/24 (island)

Cassowary:   10.0.0.10   (attacker)
Dodo:        10.0.0.101  (web server)
Takahe:      10.0.0.102  (db server)
Kiwi:        10.0.0.103  (app server)

Iris:        10.0.0.6    (DFIR-IRIS nginx)
Iris_app:    10.0.0.7    (DFIR-IRIS application)

Moa:         host-net    (monitor / packet inspection)
CICFlowMeter host-net    (flow feature extraction)
```

DFIR-IRIS also uses two internal networks for separating backend and frontend traffic:

```
iris_backend
├── iris_rabbitmq  - message broker
├── iris_db        - PostgreSQL database
├── iris_app       - IRIS application backend
└── iris_worker    - background worker

iris_frontend
├── iris_app       - IRIS application backend
└── iris           - DFIR-IRIS nginx / web UI
```

## Workflow

1. **Start environment**: `./setup_all.sh`
2. **Grab a coffee, the setup might take a while ;)**:
3. **Login to IRIS**:

```
Browser:    https://localhost
Username:   admin
Password:   psswd
```

4. **Analyse Cases and Alerts**

## Cleanup

```bash
cd infrastructure
./teardown.sh
```

## Model Information

### Original Testing

Three main evaluation setups were used in this project:

1. **2017 dataset** used for both training and testing
2. **2017 dataset** used for training and validation, with the **2018 dataset** as the training set
3. **2018 dataset** used for training and validation, with the **2017 dataset** as an additional training set

The results clearly indicate that the model trained on the **2018 dataset** (revised, https://ieeexplore.ieee.org/document/9947235) achieved the best generalization performance and robustness. This was a key finding, as there was initial uncertainty regarding how much the setup data would differ from the training data.

### Reproducing the Results

All optimization and evaluation results are stored in an Optuna db and can be visualized using:

```bash
optuna-dashboard sqlite:///optuna_trials.db
```

The scripts originally used to run the experiments are located in the `optimization_func` directory.

If you only want to generate the trained model (`.pkl` file), use the `model.py` file in the `data` directory. This file includes:

- A **testing function** for model evaluation
- A **running function** intended solely for training and saving the model

The `data` directory also contains the original dataset in JSON format.
