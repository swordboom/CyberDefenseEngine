import torch
from torch.utils.data import Dataset
from transformers import AutoModelForSequenceClassification, AutoTokenizer, Trainer, TrainingArguments


class PhishingDataset(Dataset):
    def __init__(self, rows, tokenizer, max_length=128):
        self.rows = rows
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.rows)

    def __getitem__(self, idx):
        row = self.rows[idx]
        encoded = self.tokenizer(
            f"{row['text']} [SEP] {row['url']}",
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt",
        )
        return {
            "input_ids": encoded["input_ids"].squeeze(0),
            "attention_mask": encoded["attention_mask"].squeeze(0),
            "labels": torch.tensor(row["label"], dtype=torch.long),
        }


def build_rows():
    return [
        {"text": "verify your account urgently", "url": "http://secure-login-update.com", "label": 1},
        {"text": "meeting agenda attached", "url": "https://company.com/docs", "label": 0},
        {"text": "reset password now", "url": "http://192.168.1.10/reset", "label": 1},
        {"text": "project report submitted", "url": "https://intranet.company.org/report", "label": 0},
    ]


def main():
    model_name = "distilbert-base-uncased"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    train_dataset = PhishingDataset(build_rows(), tokenizer, max_length=128)

    args = TrainingArguments(
        output_dir="artifacts/model",
        per_device_train_batch_size=2,
        num_train_epochs=1,
        logging_steps=1,
        report_to=[],
    )
    trainer = Trainer(model=model, args=args, train_dataset=train_dataset)
    trainer.train()
    trainer.save_model("artifacts/model")
    tokenizer.save_pretrained("artifacts/model")


if __name__ == "__main__":
    main()
