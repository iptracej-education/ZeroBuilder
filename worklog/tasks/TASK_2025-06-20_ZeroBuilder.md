# Tasks for Friday, June 20, 2025 (ZeroBuilder Project)

Today continues the **ZeroBuilder** project (repo: [https://github.com/iptracej-education/ZeroBuilder](https://github.com/iptracej-education/ZeroBuilder)), a 2-year solo effort (June 19, 2025–June 19, 2027, 40 hours/week) with a $10,000 cloud budget. These tasks align with **Step 0: ML Core Stack Setup** (Months 1–2), using **UV** for package management, confirming the virtual environment with Python 3.11, using GitHub Copilot, successfully processing a Joern subset, preparing a batch script for overnight execution for the dataset at `/home/iptracej/cursorDev/ZeroBuilder/sectestcases/C/testcases`, and wrapping up for the day, with tasks extending to Monday, June 23, 2025. Use Grok 3 (free, xAI) and DeepSeekCoder (free, Hugging Face), with GitHub Copilot.

## Summary of Completed Tasks and Commands
- **Tasks Completed**:
  - Set up and confirmed the virtual environment with Python 3.11.
  - Installed and tested GitHub Copilot in VS Code.
  - Successfully parsed a subset of the Juliet dataset with Joern (`CWE121_Stack_Based_Buffer_Overflow`).
  - Configured `.wslconfig` to increase WSL memory to 16 GB (15 GiB available).
  - Prepared and saved the `generate_cpg_batches.sh` script for overnight execution.
- **Commands That Worked**:
  - `sudo add-apt-repository ppa:deadsnakes/ppa -y`
  - `sudo apt update`
  - `sudo apt install python3.11 python3.11-dev python3.11-venv -y`
  - `uv init --python /usr/bin/python3.11`
  - `uv python pin 3.11`
  - `cat pyproject.toml`
  - `uv pip install torch==2.3 torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu`
  - `uv pip install setuptools --index-url https://download.pytorch.org/whl/cpu`
  - `uv sync --no-build-isolation`
  - `uv pip list`
  - `sudo apt install build-essential libatlas-base-dev -y`
  - `uv pip install torch_geometric==2.5.0 --no-build-isolation`
  - `uv run python -c "import torch; print(torch.__version__); import torchvision; print(torchvision.__version__); import torchaudio; print(torchaudio.__version__); import torch_geometric; print(torch_geometric.__version__); import stable_baselines3; print(stable_baselines3.__version__); import featuretools; print(featuretools.__version__); import xgboost; print(xgboost.__version__)"`
  - `ls -l /home/iptracej/cursorDev/ZeroBuilder/sectestcases/C/testcases`
  - `free -h`
  - `ps aux | grep joern`
  - `joern-parse /home/iptracej/cursorDev/ZeroBuilder/sectestcases/C/testcases/CWE121_Stack_Based_Buffer_Overflow/ -o cpg.bin`
  - `ls -al /home/iptracej/cursorDev/ZeroBuilder/sectestcases`
  - `chmod +x generate_cpg_batches.sh` (assumed successful setup)

- **8:48 PM–8:55 PM (0.12h)**: **Review Today’s Progress**
  - Confirm WSL Ubuntu, UV, Python 3.11, Docker setup.
  - Verify ML stack with `uv pip list` and test: `uv run python -c "..."`.
  - Check `prompts/` directories, `.gitignore`, Juliet C/C++ 1.3 dataset (updated to `/home/iptracej/cursorDev/ZeroBuilder/sectestcases`), and `conversation_2025-06-19.md`.
  - Note: Joern subset parsing succeeded; batch script to run overnight, monitor memory, and verify on Monday.
  - **Tools**: WSL terminal, text editor.
  - **Save**: `prompts/tasks/tasks_2025-06-20_review.md`.

- **8:55 PM–9:10 PM (0.25h)**: **Resolve OneDrive Sync and Confirm Virtual Environment**
  - **Move Files**: Confirm all files are moved from `~/OneDrive/.../myDev/ZeroBuilder` to `/home/iptracej/cursorDev/ZeroBuilder` (adjust `iptracej` to your username).
  - **Verify .venv**: Confirm the virtual environment exists: Check `/home/iptracej/cursorDev/ZeroBuilder/.venv`.
  - **Test Installation**: 
    - Activate: `source /home/iptracej/cursorDev/ZeroBuilder/.venv/bin/activate`.
    - Run: `uv run python -c "import torch; print(torch.__version__); import torchvision; print(torchvision.__version__); import torchaudio; print(torchaudio.__version__); import torch_geometric; print(torch_geometric.__version__); import stable_baselines3; print(stable_baselines3.__version__); import featuretools; print(featuretools.__version__); import xgboost; print(xgboost.__version__)"`.
    - Note: `pkg_resources` deprecation warning from `featuretools` can be ignored for now.
  - **Prompt DeepSeekCoder**: “Validate UV virtual environment with Python 3.11 and ML packages.”
  - **Tools**: WSL terminal, text editor.
  - **Save**: `prompts/tasks/tasks_2025-06-20_venv.md`.

- **9:10 PM–9:25 PM (0.25h)**: **Set Up GitHub Copilot**
  - Install VS Code (if not already installed) from [code.visualstudio.com](https://code.visualstudio.com/).
  - Install GitHub Copilot extension: Open VS Code, go to Extensions (Ctrl+Shift+X), search for “GitHub Copilot”, and install.
  - Sign in with your GitHub account and authorize Copilot.
  - Open the ZeroBuilder project folder (`/home/iptracej/cursorDev/ZeroBuilder`) and test Copilot with a simple suggestion (e.g., “Generate a Python function”).
  - **Prompt DeepSeekCoder**: “Validate GitHub Copilot setup.”
  - **Tools**: Browser, VS Code, WSL terminal.
  - **Save**: `prompts/codes/codes_2025-06-20_copilot.md`.

- **9:25 PM–9:40 PM (0.25h)**: **Run Joern Batch Processing Overnight with Monitoring**
  - **Set Up Batch Script**: Use the generated `generate_cpg_batches.sh`:
    ```
    #!/bin/bash

    # Base directory containing CWE folders
    BASE_DIR="/home/iptracej/cursorDev/ZeroBuilder/sectestcases/C/testcases"
    OUTPUT_DIR="/home/iptracej/cursorDev/ZeroBuilder/sectestcases"

    # Ensure output directory exists
    mkdir -p "$OUTPUT_DIR"

    # Loop through each CWE folder
    for cwe_dir in "$BASE_DIR"/CWE*; do
      if [ -d "$cwe_dir" ]; then
        cwe_name=$(basename "$cwe_dir")
        output_file="$OUTPUT_DIR/cpg_${cwe_name}.bin"
        echo "Processing $cwe_name at $(date)" >> "$OUTPUT_DIR/joern_batch_log.txt"
        joern-parse "$cwe_dir" -o "$output_file" || {
          echo "Failed to process $cwe_name at $(date), skipping..." >> "$OUTPUT_DIR/joern_batch_log.txt"
          continue
        }
        echo "Created $output_file at $(date)" >> "$OUTPUT_DIR/joern_batch_log.txt"
      fi
    done

    echo "Batch processing complete at $(date)" >> "$OUTPUT_DIR/joern_batch_log.txt"
    ```
  - **Make Executable**: Ensure it’s executable with `chmod +x /home/iptracej/cursorDev/ZeroBuilder/sectestcases/generate_cpg_batches.sh`.
  - **Run Overnight**: Execute in the background: `nohup /home/iptracej/cursorDev/ZeroBuilder/sectestcases/generate_cpg_batches.sh &` from `/home/iptracej/cursorDev/ZeroBuilder/sectestcases`.
  - **Monitor Resources**: Check memory usage with `free -h`, process status with `ps aux | grep joern`, and log with `tail -f /home/iptracej/cursorDev/ZeroBuilder/sectestcases/joern_batch_log.txt` tonight if possible.
  - **Verify Dataset Path**: Ensure `/home/iptracej/cursorDev/ZeroBuilder/sectestcases/C/testcases` exists using `ls -l /home/iptracej/cursorDev/ZeroBuilder/sectestcases/C/testcases`.
  - **Prompt Grok**: “Generate a script to monitor Joern batch processing memory and progress overnight.”
  - **Tools**: WSL terminal, text editor.
  - **Save**: `prompts/tasks/tasks_2025-06-20_joern_overnight.md`, `prompts/codes/codes_2025-06-20_generate_cpg_batches.sh`.

- **Monday, June 23, 2025 (8:00 AM–4:00 PM EDT)**: **Resume and Complete Remaining Tasks**
  - **Prepare Graph Attention Network (GAT) Pipeline, Add main.py, Test, and Push Updates**:
    - Review `joern_batch_log.txt` for completion status and any failures.
    - Verify outputs with `ls -lh /home/iptracej/cursorDev/ZeroBuilder/sectestcases/cpg_CWE*.bin`.
    - If a single `cpg.bin` is needed, rerun with `joern-parse /home/iptracej/cursorDev/ZeroBuilder/sectestcases/C/testcases -o /home/iptracej/cursorDev/ZeroBuilder/sectestcases/cpg.bin` or merge files (Grok to provide merge script).
    - Design GAT model using `torch_geometric` (Grok: “Generate GAT model skeleton for Python 3.11”).
    - Integrate with Juliet dataset CFGs (use the full `cpg.bin` or merged file).
    - Test basic forward pass on CPU (GPU delayed).
    - Create `main.py` with:
      - Import statements for PyTorch, `torch_geometric`, etc.
      - CPU check: `device = torch.device('cpu')` (GPU to be added later).
      - Call to GAT pipeline function.
    - Run `main.py` on CPU: `uv run python main.py`.
    - Verify ML stack, Joern output, and Copilot suggestions.
    - Stage and commit: `git add .`, `git commit -m "Add CFG, GAT, main.py, Copilot setup with Python 3.11"`, `git push origin main`.
    - Run validation script: `uv run python validation_script.py` to check setup.
    - Validate: Confirm accounts active, WSL Ubuntu/UV/Python 3.11/Docker installed, ML stack working, Copilot tested, repo updated, Juliet dataset at `/home/iptracej/cursorDev/ZeroBuilder/sectestcases/C/testcases` processed, and dataset present.
    - **Prompt DeepSeekCoder**: “Validate Joern CFG extraction and GAT pipeline.”
    - **Prompt Grok**: “Generate a bash script to validate Monday’s setup with Python 3.11.”
    - **Tools**: Git, WSL terminal, VS Code.
    - **Save**: `prompts/tasks/tasks_2025-06-23_cfg.md`, `prompts/codes/codes_2025-06-23_gat.md`, `prompts/codes/codes_2025-06-23_main.md`, `prompts/tasks/tasks_2025-06-23_test.md`, `prompts/tasks/tasks_2025-06-23_push.md`, `prompts/tasks/tasks_2025-06-23_validation.md`.

## Project Plan Context
- **Hardware**: WSL Ubuntu with UV (CPU-only today), Vast.ai/AWS EKS (GPU planned later).
- **Budget**: $10,000 (no cloud costs today, GPU costs deferred; no Cursor Pro cost, Claude API deferred).
- **Time**: 40 hours/week (8h/day). Today: Ended at 4:00 PM EDT; resuming Monday, June 23, 2025, 8:00 AM–4:00 PM EDT.
- **LLM Agents**: 
  - **Grok 3**: Free (xAI). 60% (code, debug).
  - **DeepSeekCoder**: Free (Hugging Face). 30% (prompts).
  - **Claude API**: Deferred (Anthropic API). 0% (future integration).
  - **GitHub Copilot**: New (VS Code integration). 10% (coding assistance).
  - **GPT-4o**: $20/month ($480 total). 0% (future tasks, delayed).
  - **Multi-Agent Loop**: Python script alternates Grok/DeepSeek, with Claude planned later.
- **Framework**: UV for package/env management, PyTorch as the ML framework with `torch==2.3.0+cpu`, `torchvision==0.18.0+cpu`, `torchaudio==2.3.0+cpu`, `torch_geometric==2.5.0`, `stable-baselines3==2.3.0`, `featuretools==1.31.0`, `xgboost==2.1.0` (all on Python 3.11).
- **Next Steps**: Move to Step 1 (Month 2) with GAT pipeline refinement (Jul 20–Jul 19, 2025), integrating Claude later.

## Validation
- Confirm Vast.ai/AWS accounts active, WSL Ubuntu/UV/Python 3.11/Docker installed, ML stack (CPU-only) working, Copilot tested, ZeroBuilder repo updated, and Juliet C/C++ 1.3 dataset at `/home/iptracej/cursorDev/ZeroBuilder/sectestcases/C/testcases` processed by end of Monday, June 23, 2025.
- **Prompt Grok**: “Generate a bash script to validate Monday’s setup with Python 3.11.”

## Support
- Query Grok for code, debugging, or explanations (e.g., “Troubleshoot overnight Joern batch failures”).
- Share progress (e.g., `joern_batch_log.txt` content or memory usage) to adjust Monday’s tasks.