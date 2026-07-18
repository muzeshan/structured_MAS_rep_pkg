# Configurations

- `prepare_secvuleval.yaml`: paired benchmark preparation.
- `development_frozen_v3_qwen3b.yaml`: exact clean-run model, budget, systems, and output settings.
- `pilot_mock.yaml`, `faults_mock.yaml`, `analysis_mock.yaml`: deterministic software smoke tests only; these outputs have no scientific meaning.

The corrected RQ3 runner uses `development_frozen_v3_qwen3b.yaml` for model and decoding settings and reads the exact included fault manifest.
