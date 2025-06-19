import os
import logging
from datetime import datetime

# Create directories if they don't exist
directories = [
    "prompts/tasks",
    "prompts/discussions",
    "prompts/codes",
    "prompts/logs"
]
for directory in directories:
    os.makedirs(directory, exist_ok=True)

# Configure logging
log_file = "prompts/logs/activity.log"
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Mock API call functions (no API keys yet)
def mock_grok_call(prompt):
    response = f"Mock Grok response for: {prompt} - Generated code/debug output"
    logging.info(f"Grok call: {prompt} -> {response}")
    return response

def mock_deepseekcoder_call(prompt):
    response = f"Mock DeepSeekCoder validation for: {prompt} - Validated prompt"
    logging.info(f"DeepSeekCoder call: {prompt} -> {response}")
    return response

# Alternating LLM loop
def llm_loop():
    tasks = [
        "Generate a hello world script",
        "Debug a Python import error",
        "Validate a configuration file"
    ]
    
    for i, task in enumerate(tasks):
        if i % 2 == 0:
            result = mock_grok_call(task)
        else:
            result = mock_deepseekcoder_call(task)
        print(result)  # Simulate output for now

if __name__ == "__main__":
    logging.info("LLM loop started at %s", datetime.now())
    llm_loop()
    logging.info("LLM loop completed at %s", datetime.now())