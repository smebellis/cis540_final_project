1. Project Objective

Build a lightweight, domain-specialized LLM capable of supporting cyber threat intelligence (CTI) tasks—specifically:

Given an APT group name, generate a complete, structured list of Indicators of Compromise (IOCs).

To achieve this, the project implemented a full PEFT/QLoRA fine-tuning pipeline on Qwen3-4B-Instruct-2507 using custom CTI datasets.

2. Environment Setup

Install:

Transformers, PEFT, bitsandbytes, accelerate, wandb

Log in to:

Hugging Face Hub

Weights & Biases

Load base model and tokenizer; validate inference works.

Configure hardware for 4-bit quantized training.

3. Training Approach

Two-stage supervised fine-tuning (SFT):

Stage 1 — IOC Extraction Skill

Dataset: instruct_ioc_qwen_clean.jsol

Goal: teach extraction of IOCs from “Observed Values” text.

Stage 2 — APT → IOC Specialization

Dataset: qwen_optimized_apt_ioc_chat.jsonl

Goal: teach the model to map APT Name → Aggregated IOC List.

Finetuning Style

QLoRA (4-bit model loading)

LoRA applied to:

q_proj, k_proj, v_proj, o_proj

gate_proj, up_proj, down_proj

5. Training Pipeline
Workflow

Normalize chat messages → unified Qwen text template.

Optionally mask non-assistant tokens (current pipeline does NOT mask).

Train/validation split.

Wrap model with PEFT/LoRA.

Configure SFTTrainer:

Batch size 1

LR = 1e-4 (Stage 1), 5e-5 (Stage 2)

16 gradient accumulation steps

2 epochs each

BF16 compute

Cosine LR schedule

W&B logging

Smoke test on small subset.

Run full training and checkpoint regularly.

Save & push LoRA adapters to Hugging Face Hub.

Log qualitative evaluations in W&B Tables.