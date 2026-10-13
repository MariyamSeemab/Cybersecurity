# PS-013: Explainable Incident Reconstruction and Evidence Correlation

A rule-based cybersecurity research prototype for correlating security events, reconstructing incident timelines, and generating findings with traceable evidence. The framework is designed to support investigations, not to provide automated verdicts.

## Features

- Security log parsing and normalization.
- Rule-based correlation of suspicious events.
- Detection of repeated failed logins, login-related PowerShell activity, and suspicious downloads.
- Evidence-based findings and incident timeline generation.
- Confidence scoring and explanation support.
- Report generation and command-line analysis.
- Baseline comparisons and rule-ablation experiments.
- Synthetic dataset generation and automated tests.

## Requirements

- Python 3.10+
- pip

## Setup (Windows PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks virtual-environment activation, use the environment's Python executable directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run the Tests

```powershell
python -m pytest -v
```

**Current test status:** 6 tests passed, 0 failed.

The tests cover:
- Handling missing optional columns during parsing.
- Detecting repeated failed logins.
- Detecting login activity followed by PowerShell.
- Validating evaluation metric bounds.
- Rejecting duplicate event IDs.
- Ensuring approved maintenance does not suppress suspicious downloads.

The current test run reports deprecation warnings associated with time-window calculations. These should be addressed in a future code cleanup.

## Generate Synthetic Data

```powershell
python -m src.generate_data
```

This generates development and test datasets with corresponding ground-truth findings.

**Important:** Both splits use the same underlying generation logic, with separate deterministic seeds. They are useful for reproducible prototype experiments but do not constitute independent real-world validation.

## Run Experiments

```powershell
python -m src.run_experiments
```

The experiment suite compares the full framework with an independent-event baseline, a time-window baseline, individual rule ablations, and a configuration without maintenance suppression.

### Current Experimental Results

The current test split contains 38 ground-truth findings.

| Method | TP | FP | FN | Precision | Recall | F1-score |
|---|---:|---:|---:|---:|---:|---:|
| Full framework | 38 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Independent-event baseline | 12 | 64 | 26 | 0.158 | 0.316 | 0.211 |
| Time-window baseline | 13 | 12 | 25 | 0.520 | 0.342 | 0.413 |
| Without R1 | 25 | 0 | 13 | 1.000 | 0.658 | 0.794 |
| Without R2 | 25 | 0 | 13 | 1.000 | 0.658 | 0.794 |
| Without R3 | 26 | 0 | 12 | 1.000 | 0.684 | 0.813 |
| Without maintenance suppression | 38 | 12 | 0 | 0.760 | 1.000 | 0.864 |

The development split produced the same metrics in the current run.

These are preliminary results on synthetic data. The generator's scenarios and ground-truth labels are structurally aligned with the detection rules, so the full framework's F1-score of 1.000 must not be interpreted as evidence of perfect real-world detection. Baseline comparisons should also account for differences in prediction granularity.

## Run the Dashboard

If the dashboard dependencies are installed and `app.py` is present:

```powershell
python -m streamlit run app.py
```

## Run Analysis Without the Dashboard

Run the command-line analysis against a CSV file:

```powershell
python -m src.cli --input data/raw_logs.csv --output reports
```

Replace `data/raw_logs.csv` with the path to your input dataset.

## Dataset Schema

Expected columns:

```text
event_id,timestamp,event_type,user,source_ip,host,details
```

- `event_id`: Unique identifier for an event.
- `timestamp`: Event timestamp parseable by pandas.
- `event_type`: Type of security event.
- `user`: Associated user identity.
- `source_ip`: Source IP address.
- `host`: Host associated with the event.
- `details`: Additional event information.

Optional values may be empty where supported by the parser. Duplicate event IDs are rejected by the current implementation.

## Project Structure

```text
PS-013/
├── data/
│   ├── development_events.csv
│   ├── development_ground_truth.csv
│   ├── test_events.csv
│   └── test_ground_truth.csv
├── results/
│   ├── metrics.csv
│   ├── findings.csv
│   └── run_metadata.json
├── src/
│   ├── log_parser.py
│   ├── correlation_engine.py
│   ├── evaluation.py
│   ├── baselines.py
│   ├── experiments.py
│   ├── generate_data.py
│   ├── run_experiments.py
│   ├── pipeline.py
│   ├── confidence_scorer.py
│   ├── explanation_engine.py
│   ├── timeline_generator.py
│   ├── report_generator.py
│   └── cli.py
├── tests/
│   └── test_pipeline.py
├── requirements.txt
└── README.md
```

The structure above lists the principal files used by the prototype and experiment suite. Additional files, such as `app.py`, may be present in the working project.

## Research Limitations and Responsible Use

- **Synthetic data:** The current experiments use generated data, not independently collected operational security logs.
- **Rule alignment:** The synthetic scenarios and labels closely reflect the programmed detection rules, which can inflate evaluation results.
- **Limited coverage:** The prototype currently evaluates a small number of predefined suspicious patterns.
- **Baseline comparability:** Prediction granularity should be checked before interpreting baseline scores as definitive comparisons.
- **Confidence scores:** A confidence score is an evidence-strength heuristic, not a calibrated probability unless separately validated.
- **Investigative use:** Rule matches are leads for investigation, not proof of compromise.
- **No automated verdicts:** Do not use the prototype to make automated disciplinary, legal, or access-control decisions.
- **No production claim:** Passing automated tests does not establish production readiness or real-world detection effectiveness.

## Future Work

- Validate against independent cybersecurity datasets.
- Expand suspicious and benign event scenarios.
- Standardize evaluation granularity across baselines.
- Evaluate explanation quality and confidence calibration.
- Test robustness to missing, duplicated, or noisy events.
- Investigate scalability and processing latency.
- Resolve outstanding deprecation warnings.

## License and Data Availability

Add the applicable license and data/code availability statement before public release. Do not claim a license or unrestricted data availability unless it has been explicitly established.
