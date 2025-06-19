# Tasks for Thursday, June 19, 2025 (ZeroBuilder Project)

Today marks the beginning of the **ZeroBuilder** project (repo: [https://github.com/iptracej-education/ZeroBuilder](https://github.com/iptracej-education/ZeroBuilder)), a 2-year solo effort (June 19, 2025–June 19, 2027, 40 hours/week) with a $10,000 cloud budget. These tasks align with **Step 0: ML Core Stack Setup** (Months 1–2), using **UV** for package management, preparing the repository with the `prompts` directory, within ~3.22 hours (2:47 PM–6:00 PM EDT) to avoid costs until GPU code is ready. Use Grok 3 (free, xAI) and DeepSeekCoder (free, Hugging Face), delaying GPT-4o ($20/month).

- **2:47 PM–3:15 PM (0.47h)**: **Set Up Cloud and Platform Accounts**
  - Sign up for Vast.ai at [vast.ai](https://vast.ai) (free until instance activation).
  - Create AWS account at [aws.amazon.com](https://aws.amazon.com) (free until EKS spin-up).
  - Create Hugging Face account at [huggingface.co](https://huggingface.co) for DeepSeekCoder (free).
  - Create GitHub account (if not done) and link to ZeroBuilder repo.
  - **Prompt Grok**: “Generate a checklist for Vast.ai, AWS, Hugging Face, and GitHub sign-ups.”
  - **Tools**: Browser, email.
  - **Save**: `prompts/tasks/tasks_2025-06-19_signups.md`.

- **3:15 PM–4:45 PM (1.5h)**: **Set Up New WSL Ubuntu with UV**
  - Install Ubuntu 22.04 in WSL on Windows:
    - Open PowerShell as admin: `wsl --install`.
    - Download Ubuntu 22.04 from Microsoft Store, launch, and set username/password (e.g., `iptracej`).
    - Update: `sudo apt update && sudo apt upgrade -y`.
  - Install UV: `curl -LsSf https://astral.sh/uv/install.sh | sh` (Grok: “Generate bash script for UV installation”).
  - Install Python 3.12 and Docker: `sudo apt install python3.12 python3-pip docker.io` (Grok for script).
  - Verify: `uv --version`, `python3 --version`, `docker --version`.
  - **Prompt Grok**: “Guide for WSL Ubuntu 22.04 setup with UV.”
  - **Prompt DeepSeekCoder**: “Validate WSL and UV setup commands.”
  - **Tools**: PowerShell, Microsoft Store, WSL terminal.
  - **Save**: `prompts/tasks/tasks_2025-06-19_wslsetup.md`.

- **4:45 PM–5:15 PM (0.5h)**: **Install and Validate Local ML Stack with UV**
  - Navigate to ZeroBuilder repo root (`~/myDev/ZeroBuilder` in WSL).
  - Confirm `.venv` exists (created by `uv sync`); if not, run `uv sync --verbose` to recreate.
  - Update `pyproject.toml` with dependencies:
    ```
    [project]
    name = "zerobuilder"
    version = "0.1.0"

    [tool.uv.dependencies]
    torch = "2.3"
    torchvision = "*"
    torchaudio = "*"
    markupsafe = "2.1.5"
    setuptools = "*"
    pytorch_geometric = "2.5.0"
    stable-baselines3 = "2.2.1"
    featuretools = "1.31"
    xgboost = "2.1"
    ```
  - Set default index: `uv config --set-default-index https://download.pytorch.org/whl/cpu`.
  - Sync environment: `uv sync`.
  - Activate environment: `source .venv/bin/activate` (already active as `zerobuilder`).
  - Verify packages: `uv pip list` (expect `torch==2.3.0+cu121`, `torchvision==0.18.0+cu121`, `torchaudio==2.3.0+cu121`, `pyg-lib`, `torch-scatter`, `torch-sparse`, `torch-cluster`, `torch-spline-conv`, `torch_geometric==2.6.1`, `stable-baselines3==2.2.1`, `featuretools==1.31.0`, `xgboost==2.1.0`).
  - Test installations: `uv run python -c "import torch; print(torch.__version__); import torchvision; print(torchvision.__version__); import torchaudio; print(torchaudio.__version__); import torch_geometric; print(torch_geometric.__version__); import stable_baselines3; print(stable_baselines3.__version__); import featuretools; print(featuretools.__version__); import xgboost; print(xgboost.__version__)"`.
  - **Warnings**: 
    - `pkg_resources` deprecation (Setuptools): Ignore for now; update later if needed.
    - Invalid escape sequence `\l` in `featuretools`: Syntax warning, not critical; report if persistent.
  - **Prompt Grok**: “Generate Python script to test UV-managed ML stack, log results, and note warnings.”
  - **Prompt DeepSeekCoder**: “Validate UV ML stack with warnings.”
  - **Tools**: WSL terminal, text editor.
  - **Save**: `prompts/tasks/tasks_2025-06-19_mlstack.md`.

- **5:15 PM–5:45 PM (0.5h)**: **Initialize Multi-Agent LLM Loop and Prompt Directory**
  - Confirm `llm_loop_script.py` ran successfully, creating `prompts/tasks`, `prompts/discussions`, `prompts/codes`, `prompts/logs`, and logging to `prompts/logs/activity.log`.
  - Verify log file content: Check `activity.log` for entries like “Mock Grok response” and “Mock DeepSeekCoder validation”.
  - Update script if needed (Grok: “Enhance llm_loop_script.py with more tasks”).
  - Delay GPT-4o API setup until GPU code is ready.
  - Create `prompts/README.md` (Grok: “Write README for prompt directory structure”).
  - **Tools**: Text editor, terminal.
  - **Save**: `prompts/codes/codes_2025-06-19_llmloop.md` (updated script if modified), `prompts/discussions/discussions_2025-06-19_readme.md`.

- **5:45 PM–6:05 PM (0.33h)**: **Prepare ZeroBuilder Repository and Data with .gitignore**
  - Initialize ZeroBuilder repo locally: `git init`.
  - Create `.gitignore` with the updated content (including `uv.lock`) and save in `~/myDev/ZeroBuilder`.
  - Check `git status` to confirm `prompts` directory and files are untracked.
  - Stage and commit: `git add prompts/ README.md .gitignore`, `git commit -m "Add prompts directory, README, and .gitignore"`.
  - Push to repo: `git push origin main` (ensure remote is set, e.g., `git remote add origin <repo-url>` if not done).
  - If `prompts` isn’t staged, add specific files (e.g., `git add prompts/tasks/*`) or ensure directories aren’t empty (add `.gitkeep` if needed).
  - Download Juliet dataset (~1GB) from [https://samate.nist.gov](https://samate.nist.gov) and store locally.
  - **Prompt Grok**: “Generate git commands for ZeroBuilder repo and script to download Juliet dataset.”
  - **Prompt DeepSeekCoder**: “Validate Juliet dataset download script.”
  - **Tools**: Git, browser, text editor.
  - **Save**: `prompts/tasks/tasks_2025-06-19_repodata.md`.

- **6:05 PM–6:15 PM (0.17h)**: **Plan Tomorrow’s Tasks and Validate Setup**
  - Draft tomorrow’s tasks (e.g., Joern CFG extraction, GAT prep, add `main.py` skeleton) in `prompts/tasks/TODO_2025-06-20.md`.
  - Validate setup: Check accounts, WSL Ubuntu/UV/Python/Docker, ML stack, LLM loop, repo (confirm `prompts` pushed), and dataset.
  - **Prompt Grok**: “Generate a validation script to check accounts, WSL UV setup, ML stack, and dataset, and create TODO_2025-06-20.md in prompts/tasks.”
  - **Tools**: Text editor, terminal.
  - **Save**: `prompts/tasks/tasks_2025-06-19_validation.md`.

## Project Plan Context
- **Hardware**: Cloud-based (Vast.ai 1x A100, AWS EKS) activated later. New WSL Ubuntu with UV for ZeroBuilder.
- **Budget**: $10,000 (no cost today, deferred until Vast.ai/AWS use).
- **Time**: 40 hours/week (8h/day). Today: ~3.22 hours remaining (2:47 PM–6:00 PM EDT).
- **LLM Agents**:
  - **Grok 3**: Free (xAI). 60% (code, debug).
  - **DeepSeekCoder**: Free (Hugging Face). 30% (prompts).
  - **GPT-4o**: $20/month ($480 total). 10% (future tasks, delayed).
  - **Multi-Agent Loop**: Python script (Task 4) alternates Grok/DeepSeek.
- **Next Steps**: Continue Step 0 (Month 2) with GAT pipeline (Jul 20–Jul 19, 2025) after validation, including `main.py`.

## Validation
- Confirm Vast.ai/AWS/Hugging Face/GitHub accounts active, WSL Ubuntu/UV/Python/Docker installed, ML stack (CPU-only) working, LLM loop tested, ZeroBuilder repo initialized with `prompts/` structure, `.gitignore` (ignoring `uv.lock`), and Juliet dataset downloaded by 6:00 PM EDT.
- **Prompt Grok**: “Generate a bash script to validate today’s WSL UV setup and create TODO_2025-06-20.md.”

## Support
- Query Grok for code, debugging, or explanations (e.g., “Troubleshoot prompts push failure”).
- Share progress (e.g., `git status` output) to adjust tomorrow’s tasks.