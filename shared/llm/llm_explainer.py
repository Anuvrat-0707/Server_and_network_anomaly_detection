import requests

import os
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
url = "https://api.groq.com/openai/v1/chat/completions"

def query_groq_for_app_explanation(top_app_name, top_value, current_explanation, metric="memory"):
    try:
        top_value = float(top_value)
    except:
        return "Invalid value for app usage."

    prompt_map = {
        "memory": f"""
The system has detected high memory usage.  
The application using the most memory is '{top_app_name}' with a usage of {top_value:.2f} MB.

Explain clearly why this app might be consuming such high memory. Include possible technical causes such as:
- memory leaks  
- inefficient data structures  
- background threads  
- heavy computations  
- system misconfiguration
""",
        "cpu": f"""
The system has detected high CPU usage.  
The application using the most CPU is '{top_app_name}' at {top_value:.2f}% CPU.

Explain clearly why this app might be consuming so much CPU. Include possible technical causes such as:
- infinite loops
- inefficient algorithms
- background threads
- stuck or zombie processes
- driver or system misconfigurations
""",
        "disk": f"""
The system has detected high disk usage.  
The application using the most disk is '{top_app_name}' with I/O usage of {top_value:.2f} MB/sec.

Explain clearly why this app might be consuming so much disk. Include causes like:
- heavy read/write operations
- logging loops
- large file generation
- database I/O spikes
"""
    }

    extra_prompt = prompt_map.get(metric.lower(), prompt_map["memory"])
    full_prompt = current_explanation.strip() + "\n\n✅ Add to the above:\n" + extra_prompt.strip()

    # Debug print
    print("=== Prompt Sent to Groq ===")
    print(full_prompt)

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "model": "llama3-70b-8192",
        "messages": [
            {
                "role": "system",
                "content": "You are an expert system analyst. Explain the likely technical cause for application resource spikes."
            },
            {
                "role": "user",
                "content": full_prompt
            }
        ],
        "temperature": 0.5
    }

    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        return result['choices'][0]['message']['content']
    except requests.exceptions.RequestException as e:
        print("❌ Error calling Groq API:", e)
        if e.response is not None:
            print("🔍 Response content:", e.response.text)
        return "LLM explanation failed (request error)."
    except Exception as e:
        print("❌ Unexpected error:", e)
        return "LLM explanation failed (unexpected error)."
