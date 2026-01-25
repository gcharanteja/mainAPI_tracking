# main.py

import pandas as pd
import numpy as np
from datasets import Dataset, DatasetDict
import json
import os
from pck67_pkg import TrackingClient

# ---------------------------
# Initialize Tracking Client
# ---------------------------
client = TrackingClient(
    api_key="0c744e2786702c362745fc032ec9dc0912e9bdad1830fa424aa4261b7204720a",
    base_url="http://13.64.248.226:8000"
)

# Start a run
run = client.init_run(project_id=1, name="Logistics Data Generation", config={"task": "synthetic_logistics"})

# ---------------------------
# Generate Synthetic Logistics Data
# ---------------------------

np.random.seed(42)

statuses = ["pending", "processing", "in_transit", "delayed", "delivered", "lost", "returned"]
regions = ["North", "South", "East", "West", "Central"]
carriers = ["FedEx", "UPS", "DHL", "Local", "Express"]
priority_levels = ["standard", "express", "overnight"]

def generate_sample(idx):
    """Generate a single logistics order record."""
    status = np.random.choice(statuses)
    region = np.random.choice(regions)
    carrier = np.random.choice(carriers)
    priority = np.random.choice(priority_levels)
    days_in_transit = np.random.randint(1, 14)

    order_text = f"Order #{idx:05d}: Shipped via {carrier} ({priority}) to {region} region. Status: {status}. Days in transit: {days_in_transit}."

    if status in ["delivered"]:
        label = 2
    elif status in ["delayed", "lost", "returned"]:
        label = 0
    else:
        label = 1

    return {
        "text": order_text,
        "status": status,
        "region": region,
        "carrier": carrier,
        "priority": priority,
        "days": days_in_transit,
        "label": label
    }

# Generate 10,000 samples
msg = "Generating 10,000 logistics order samples..."
print(msg)
client.log_message(run.id, msg, step=1)

samples = [generate_sample(i) for i in range(10000)]
df = pd.DataFrame(samples)

# Save raw CSV
raw_path = "data/raw/logistics_orders.csv"
os.makedirs("data/raw", exist_ok=True)
df.to_csv(raw_path, index=False)

msg = f"✓ Saved raw data: {raw_path}"
print(msg)
client.log_message(run.id, msg, step=2)

msg = f"  Shape: {df.shape}"
print(msg)
client.log_message(run.id, msg, step=3)

msg = f"\nLabel distribution:\n{df['label'].value_counts()}"
print(msg)
client.log_message(run.id, msg, step=4)

# Create HuggingFace Dataset
train_test_split = 0.8
split_idx = int(len(df) * train_test_split)

train_df = df[:split_idx]
test_df = df[split_idx:]

train_dataset = Dataset.from_pandas(train_df[["text", "label"]])
test_dataset = Dataset.from_pandas(test_df[["text", "label"]])

dataset_dict = DatasetDict({
    "train": train_dataset,
    "validation": test_dataset
})

# Save datasets locally
dataset_path = "data/processed/logistics_dataset"
os.makedirs("data/processed", exist_ok=True)
dataset_dict.save_to_disk(dataset_path)

msg = f"\n✓ Saved HuggingFace datasets: {dataset_path}"
print(msg)
client.log_message(run.id, msg, step=5)

msg = f"  Train: {len(train_dataset)} samples"
print(msg)
client.log_message(run.id, msg, step=6)

msg = f"  Validation: {len(test_dataset)} samples"
print(msg)
client.log_message(run.id, msg, step=7)

# Finish run
run.finish()

# Optionally fetch aggregated metrics (numeric only)
aggregated = run.get_aggregated_metrics()
print("Aggregated metrics:", aggregated)