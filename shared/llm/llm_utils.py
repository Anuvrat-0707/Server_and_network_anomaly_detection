from shared.llm.llm_explainer import query_groq_for_app_explanation

def explain_anomaly_via_llm(row):
    anomaly_type = row.get("anomaly_type", "")
    cpu = float(row.get("cpu", 0))
    memory = float(row.get("memory", 0))
    disk = float(row.get("disk", 0))

    # Determine most stressed metric
    if "CPU" in anomaly_type or (cpu > memory and cpu > disk):
        metric = "cpu"
        value = cpu
    elif "Memory" in anomaly_type or (memory > cpu and memory > disk):
        metric = "memory"
        value = memory
    elif "Disk" in anomaly_type or (disk > cpu and disk > memory):
        metric = "disk"
        value = disk
    else:
        metric = None
        value = 0

    # Extract app name from dict or fallback
    top_app = row.get("top_app_name", "Unknown")
    if isinstance(top_app, dict):
        app_name = top_app.get("name", "Unknown")
    else:
        app_name = top_app  # fallback to string

    # Generate explanation if metric identified
    if metric:
        base_prompt = f"Anomaly Detected: {anomaly_type}. {metric.upper()} usage reached {round(value, 2)}%."
        return query_groq_for_app_explanation(app_name, round(value, 2), base_prompt, metric)
    else:
        return f"Anomaly detected: {anomaly_type}. Unable to determine specific resource."
