# Baseline Profiles

The auditor loads its baseline from JSON rather than requiring every threshold
to be changed in Python source code.

The bundled `default.json` profile preserves the original 15 checks. It is a
custom educational baseline and is **not** a formal CIS Benchmark or NIST
certification profile.

## Selecting a profile

```bash
python3 baseline_auditor.py samples/secure_linux \
  --profile default \
  -o output_secure
```

A path to a custom profile may also be supplied:

```bash
python3 baseline_auditor.py exported_host \
  --profile profiles/my-custom-profile.json \
  -o output_custom
```

List bundled profiles:

```bash
python3 baseline_auditor.py --list-profiles
```

## Supported key/value operators

- `equals`
- `in`
- `int_between`
- `int_gte`
- `int_lte`

The `firewall_status` and `file_permissions` parsers use specialized rule
blocks because their inputs are not ordinary key/value configuration files.

Copy `default.json`, assign a new `profile_id`, and change thresholds or
expected values to create an organizational profile. Any mapping to a formal
framework should be independently validated before being represented as a
CIS, NIST, or other compliance profile.
