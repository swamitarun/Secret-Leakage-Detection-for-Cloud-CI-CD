# Final Evaluation Report

Date: 2026-10-03

## Executive Result

The project is operational as a local research prototype and secure ZIP scanning workflow. The deterministic context-aware rules engine is the strongest decision layer on the project-specific IaC/CI-CD benchmark. The Transformer is available as semantic evidence and performs strongly on the held-out Prowl test split, but its custom-benchmark false-positive rate is too high to use as the sole decision maker.

No additional training was performed in this validation pass. The existing production checkpoint was verified and is stronger than the 10k smoke checkpoint.

## Verified Artifacts

- Production model: `reports/transformer_secret_detector.pt`
- Production training history: `reports/training_history.json`
- Custom benchmark metrics: `reports/benchmark_results.json`
- Ablation metrics: `reports/ablation_results.json`
- Scanner report: `reports/scan_report.json`
- Human-readable scanner report: `reports/scan_report.html`
- Smoke checkpoint: `reports/checkpoints/prowl_10k_smoke.pt`

## Training and Held-out Prowl Test

The production checkpoint was trained with 15,000 samples, validated on 4,000 samples, and tested on 4,000 samples for 3 epochs. The stored test result is:

| Metric | Value |
|---|---:|
| Accuracy | 0.9670 |
| Precision | 0.9647 |
| Recall | 0.9695 |
| F1 | 0.9671 |
| ROC-AUC | 0.9943 |
| True negatives | 1,929 |
| False positives | 71 |
| False negatives | 61 |
| True positives | 1,939 |
| False-positive rate | 0.0355 |
| False-negative rate | 0.0305 |
| Test loss | 0.1191 |

These numbers are copied from the saved training artifact. They are not a claim about every real repository or every secret provider.

## Custom IaC/CI-CD Benchmark

The benchmark contains 600 synthetic/public-safe examples across Terraform, CloudFormation, GitHub Actions, Jenkins, GitLab CI, and documentation. It contains 270 positive and 330 negative examples.

| Method | Accuracy | Precision | Recall | F1 | False positives | False negatives | Latency/sample |
|---|---:|---:|---:|---:|---:|---:|---:|
| Regex only | 0.7833 | 0.6750 | 1.0000 | 0.8060 | 130 | 0 | 0.035 ms |
| Regex + entropy | 0.7833 | 0.6750 | 1.0000 | 0.8060 | 130 | 0 | 0.051 ms |
| Regex + entropy + IaC | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0 | 0 | 0.062 ms |
| Context-aware rules | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0 | 0 | 3.543 ms |
| Transformer only | 0.6517 | 0.5648 | 0.9852 | 0.7179 | 205 | 4 | 2.543 ms |
| Hybrid Transformer + rules | 0.6583 | 0.5684 | 1.0000 | 0.7248 | 205 | 0 | 6.350 ms |

The perfect rules score is expected on this synthetic benchmark and should not be generalized to unseen production repositories. The Transformer/hybrid result shows that domain-specific IaC/CI-CD calibration remains necessary.

## Ablation Study

| Configuration | Accuracy | Precision | Recall | F1 | False positives | False negatives |
|---|---:|---:|---:|---:|---:|---:|
| Full hybrid | 0.6583 | 0.5684 | 1.0000 | 0.7248 | 205 | 0 |
| Without IaC resource context | 0.6550 | 0.5666 | 0.9926 | 0.7214 | 205 | 2 |
| Without CI/CD context | 0.6583 | 0.5684 | 1.0000 | 0.7248 | 205 | 0 |
| Without entropy | 0.6533 | 0.5657 | 0.9889 | 0.7197 | 205 | 3 |
| Without Transformer | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0 | 0 |

The ablation indicates that entropy and IaC context affect recall on this benchmark. CI/CD removal has no measurable effect here because the generated cases are easy for the remaining signals. A larger, harder benchmark is required before making broader causal claims.

## Scanner Output Verification

The final fixture scan used the production checkpoint and produced:

- SAFE: 4
- CRITICAL: 3
- Model evidence available: 7/7 files
- Real secret values: not written to JSON, HTML, or SARIF
- Reports: JSON, HTML, and SARIF generated successfully

The final risk level remains controlled by deterministic rules and context. Transformer probability is supporting evidence, not an unexplained replacement for the risk engine.

## How It Works

1. A local path or ZIP is supplied to the scanner.
2. ZIP validation checks compressed size, extracted size, file count, path traversal, symlinks, and supported extensions.
3. Supported files are extracted into a temporary directory.
4. Regex patterns identify candidate secret types.
5. Shannon entropy estimates value randomness.
6. Placeholder/test/documentation filters reduce false positives.
7. IaC and CI/CD analysis identifies Terraform, CloudFormation, AWS resources, workflows, and deployment context.
8. The risk engine adds configured positive and negative factors and clamps the score to 0-100.
9. Optional Transformer inference returns semantic secret probability and confidence.
10. Reports expose findings, line numbers, risk factors, and model evidence without secret values.
11. Temporary ZIP content is deleted after scanning.
12. CI exits non-zero for configured severity and can upload SARIF to GitHub Code Scanning.

## Mathematics

For a candidate string with character probabilities $p_i$, Shannon entropy is:

$$H(X) = -\sum_i p_i \log_2(p_i)$$

The deterministic risk score is:

$$S = \min(100, \max(0, \sum positive\ factors + \sum reductions))$$

The binary metrics are:

$$Accuracy = \frac{TP + TN}{TP + TN + FP + FN}$$

$$Precision = \frac{TP}{TP + FP}$$

$$Recall = \frac{TP}{TP + FN}$$

$$F1 = \frac{2 \cdot Precision \cdot Recall}{Precision + Recall}$$

ROC-AUC is the area under the true-positive-rate versus false-positive-rate curve across classifier thresholds. It was measured for the Prowl test result and is not claimed for the custom benchmark because that benchmark artifact stores hard predictions without probability scores for every comparison method.

## Validation Status

- Existing scanner suite: 13/13 passed
- ZIP security suite: passed
- SARIF redaction suite: passed
- Full Python compilation: passed
- Dashboard startup: passed
- Realistic synthetic ZIP workflow: passed
- Temporary extraction cleanup: verified

## Decision

Do not retrain only to increase a headline number. The current production checkpoint is acceptable as semantic evidence on the held-out Prowl split. Before a real security product launch, collect a larger organization-specific IaC/CI-CD validation set, calibrate thresholds, test unseen providers and repository layouts, and measure false positives separately per file type and secret family.

## Hardware Decision

| Work | Laptop CPU | GPU server |
|---|---|---|
| Regex, entropy, IaC, CI/CD scan | Yes | Yes |
| ZIP upload and cleanup | Yes | Yes |
| Streamlit dashboard | Yes | Yes |
| Unit and security tests | Yes | Yes |
| Transformer inference | Yes, slower | Yes, faster |
| Prowl training | Possible but impractical | Recommended |
| Large benchmark/evaluation | Possible | Recommended |

The laptop only needs the source tree and optionally the 477 MB production
checkpoint. Keep the server's 5.5 GB virtual environment and 278 MB Prowl
cache on the server. Recreate environments from the requirements files instead
of copying `.venv` between machines.
