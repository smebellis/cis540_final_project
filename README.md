# cis540_final_project
Project-4: Building custom LLM for cyber threat intelligence

Set up environment (Transformers, PEFT, bitsandbytes, accelerate, wandb).

Log in to Hugging Face Hub + W&B.

Download chatgpt-oss-20b model + tokenizer; confirm inference works.

Define objective (SFT vs domain LM).

Build dataset:

Normalize chat turns → unified text template.

Tokenize.

Mask non-target tokens with -100 in labels.

Train/val split.

Choose finetuning style (LoRA first).

Wrap model with LoRA using PEFT (optionally 4-bit load).

Configure Trainer:

TrainingArguments (batch size, lr, fp16/bf16, logging_steps, save_steps, wandb).

DataCollator for causal LM.

train + eval datasets.

Run a smoke test on a tiny subset, confirm W&B logs + no OOM.

Run full training, checkpointing periodically.

Save/merge adapter weights, tokenizer, and chat template.

Evaluate generations vs baseline and capture examples in W&B Tables.

(Optional) Push adapter + model card to Hugging Face Hub.
