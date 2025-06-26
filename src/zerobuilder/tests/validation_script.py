import os
import subprocess
import logging
from datetime import datetime
import importlib
import sys
import shutil

def setup_logging(log_file):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def log_and_print(msg, level="info"):
    print(msg)
    getattr(logging, level)(msg)

def check_accounts(accounts, account_files):
    for account, file_path in zip(accounts, account_files):
        status = os.path.exists(file_path)
        msg = f"{account.upper()} account: {'Active' if status else 'Not found'}"
        log_and_print(msg, "info")

def check_binaries(binaries):
    for binary in binaries:
        if not shutil.which(binary):
            log_and_print(f"Required binary '{binary}' not found in PATH.", "error")
            return False
    return True

def check_env():
    try:
        wsl_check = subprocess.run(["uname", "-a"], capture_output=True, text=True).stdout
        uv_version = subprocess.run(["uv", "--version"], capture_output=True, text=True).stdout.strip()
        python_version = subprocess.run(["python3", "--version"], capture_output=True, text=True).stdout.strip()
        docker_version = subprocess.run(["docker", "--version"], capture_output=True, text=True).stdout.strip()
        logging.info(f"WSL check: {wsl_check}")
        logging.info(f"UV version: {uv_version}")
        logging.info(f"Python version: {python_version}")
        logging.info(f"Docker version: {docker_version}")
        log_and_print("WSL/UV/Python/Docker setup: Validated", "info")
        return True
    except FileNotFoundError as e:
        log_and_print(f"Setup check failed: {e}", "error")
        return False
    except Exception as e:
        log_and_print(f"Unexpected error during env check: {e}", "error")
        return False

def check_ml_stack(ml_packages):
    ml_valid = True
    for pkg, expected_ver in ml_packages.items():
        try:
            module = importlib.import_module(pkg)
            actual_ver = getattr(module, "__version__", str(module.__version__))
            if actual_ver != expected_ver:
                log_and_print(f"{pkg} version mismatch: expected {expected_ver}, got {actual_ver}", "warning")
                ml_valid = False
            else:
                log_and_print(f"{pkg} version: {actual_ver}", "info")
        except ImportError:
            log_and_print(f"Failed to import {pkg}", "error")
            ml_valid = False
        except Exception as e:
            log_and_print(f"Error checking {pkg}: {e}", "error")
            ml_valid = False
    if ml_valid:
        log_and_print("ML stack: Validated", "info")
    return ml_valid

def check_dataset(dataset_path):
    dataset_exists = os.path.exists(os.path.expanduser(dataset_path))
    msg = f"Juliet dataset: {'Present' if dataset_exists else 'Missing'}"
    log_and_print(msg, "info")
    return dataset_exists

def create_todo(todo_file, todo_content):
    os.makedirs(os.path.dirname(todo_file), exist_ok=True)
    with open(todo_file, "w") as f:
        f.write(todo_content)
    log_and_print(f"Created {todo_file}", "info")

def main():
    log_file = "prompts/logs/validation.log"
    setup_logging(log_file)

    accounts = ["vast.ai", "aws", "huggingface", "github"]
    account_files = ["/tmp/vastai_setup", "/tmp/aws_setup", "/tmp/hf_setup", "/tmp/gh_setup"]
    check_accounts(accounts, account_files)

    env_ok = check_env()

    ml_packages = {
        "torch": "2.3.0+cu121",
        "torchvision": "0.18.0+cu121",
        "torchaudio": "2.3.0+cu121",
        "torch_geometric": "2.6.1",
        "stable_baselines3": "2.2.1",
        "featuretools": "1.31.0",
        "xgboost": "2.1.0"
    }
    ml_ok = check_ml_stack(ml_packages)

    dataset_path = "~/myDev/ZeroBuilder/juliet_dataset"
    dataset_ok = check_dataset(dataset_path)

    todo_file = os.path.join("prompts/tasks", "TODO_2025-06-20.md")
    todo_content = """# TODO for Friday, June 20, 2025 (ZeroBuilder Project)

- [ ] Extract control flow graphs (CFG) using Joern
- [ ] Prepare Graph Attention Network (GAT) pipeline
- [ ] Add skeleton for main.py with initial logic
"""
    create_todo(todo_file, todo_content)

    logging.info("Validation completed at %s", datetime.now())
    print("Validation completed")

    # Exit code for CI/CD
    if not (env_ok and ml_ok and dataset_ok):
        sys.exit(1)

if __name__ == "__main__":
    main()