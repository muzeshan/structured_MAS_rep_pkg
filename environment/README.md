# Environments

For result verification only:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r environment/requirements-analysis.txt
```

For GPU generation on a CUDA-capable Linux host or Google Colab:

```bash
pip install -e '.[test]'
```

The reported model is `Qwen/Qwen2.5-Coder-3B-Instruct` at revision
`488639f1ff808d1d3d0ba301aef8c11461451ec5`, loaded in 4-bit mode. The
configuration uses deterministic decoding (`do_sample: false`, temperature
0) and stage ceilings of 340/220/480 tokens.
