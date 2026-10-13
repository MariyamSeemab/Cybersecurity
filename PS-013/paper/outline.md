# PS-013 Research Paper Outline

## Working title
Explainable Incident Reconstruction and Evidence Correlation Framework for Automated Cybersecurity Investigations

## Research question
How effectively can an explainable evidence-correlation framework reconstruct cyber incident timelines and reduce investigation effort compared with manual log analysis?

## Abstract
Write after experiments. Include the problem, proposed method, dataset characteristics, evaluation metrics, measured results, and limitations. Do not invent results.

## 1. Introduction
- Problem: analysts must connect fragmented events across logs.
- Research gap: evaluate whether explicit evidence links and rule explanations improve traceability in a lightweight reconstruction workflow.
- Research question and contributions.

## 2. Related Work
- Digital forensics and incident response (DFIR).
- Security event correlation and timeline reconstruction.
- Explainable security analytics.
- Position the work carefully; do not claim novelty without a documented comparison.

## 3. Framework Design
- Input schema and normalization.
- Rule-based correlation.
- Timeline generation.
- Evidence-strength heuristic and explanation generation.
- HTML/Streamlit presentation.

## 4. Experimental Methodology
- Clearly label synthetic data and describe how scenarios were generated.
- Define ground truth before evaluation.
- Baselines, test cases, thresholds, and time windows.
- Precision, recall, F1, event-level metrics, timeline ordering, and investigation time.
- Report software versions and reproducibility steps.

## 5. Results and Discussion
- Report measured results only.
- Include errors and false positives, not just successful cases.
- Compare the framework to the baseline using the same scenarios.

## 6. Limitations and Threats to Validity
- Small and synthetic dataset.
- Rule coverage and threshold sensitivity.
- Heuristic score is not a calibrated probability.
- Time savings cannot be generalized without representative participants and cases.

## 7. Conclusion and Future Work
- Summarize what the experiment demonstrates.
- Propose public dataset validation, richer event normalization, and calibration as future work.

## Ethics and data handling
Use synthetic or authorized, sanitized logs. Do not include real credentials, personal data, or sensitive incident details.
