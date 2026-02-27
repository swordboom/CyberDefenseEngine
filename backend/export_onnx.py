import os
import sys
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer


def main(model_dir="artifacts/model", output_path="artifacts/distilbert_phishing.onnx"):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    tokenizer = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir)
    model.eval()
    encoded = tokenizer("sample [SEP] https://example.com", return_tensors="pt", max_length=128, truncation=True)
    os.makedirs("artifacts", exist_ok=True)
    torch.onnx.export(
        model,
        (encoded["input_ids"], encoded["attention_mask"]),
        output_path,
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "sequence"},
            "attention_mask": {0: "batch", 1: "sequence"},
            "logits": {0: "batch"},
        },
        opset_version=18,
        dynamo=False,
    )
    print(f"Saved ONNX model to {output_path}")


if __name__ == "__main__":
    main()
