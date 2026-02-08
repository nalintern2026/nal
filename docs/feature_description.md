## Feature Descriptions

Document all engineered features and encodings:
- Name
- Definition / formula
- Data type and units
- Expected range
- Handling of missing/invalid values
- Notes on scaling/encoding

Example entry:
```
feature: pkt_rate
definition: packets / flow_duration_seconds
type: float
range: >= 0
missing: drop flows with duration == 0
scaling: standard scaler
```