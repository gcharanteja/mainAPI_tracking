import pandas as pd
import numpy as np
import logging
from logger import auto_track_module
import traceback
import sys

# Automatically set up tracking for this module using shared team/project
logger = auto_track_module(
    module_name="usage.py",
    team_name="example Team",
    project_name="example Project",
    run_name="comprehensive_test",
    config={"task": "test_all_log_levels", "version": "2.0"}
)

print("=" * 60)
print("🔬 COMPREHENSIVE LOGGING TEST")
print("=" * 60)

# --- 1. DEBUG LEVEL ---
logger.debug("🐛 DEBUG: Starting experiment initialization...")
logger.debug("🐛 DEBUG: Loading configuration from config.yaml")
logger.debug("🐛 DEBUG: GPU device check - found 0 devices")

# --- 2. INFO LEVEL ---
logger.info("ℹ️ INFO: Experiment started on Jan 23 2026")
logger.info("ℹ️ INFO: Training on dataset: MNIST (60,000 samples)")
logger.info("ℹ️ INFO: Model architecture: ResNet-50")
logger.info("ℹ️ INFO: Hyperparameters: lr=0.001, batch_size=32, epochs=10")

# --- 3. WARNING LEVEL ---
logger.warning("⚠️ WARNING: GPU not available, using CPU instead")
logger.warning("⚠️ WARNING: Training data has 5% missing values")
logger.warning("⚠️ WARNING: Model checkpoint from previous run not found")
logger.warning("⚠️ WARNING: Learning rate may be too high (0.1)")

# --- 4. ERROR LEVEL ---
logger.error("❌ ERROR: Failed to load pretrained weights from checkpoint")
logger.error("❌ ERROR: Validation loss increased for 3 consecutive epochs")
logger.error("❌ ERROR: Out of memory error at batch 150")

# --- 5. CRITICAL LEVEL ---
logger.critical("🔥 CRITICAL: Training crashed due to CUDA out of memory!")
logger.critical("🔥 CRITICAL: Database connection lost - cannot save metrics")
logger.critical("🔥 CRITICAL: Disk space full - cannot write checkpoint")

print("\n" + "=" * 60)
print("🧪 EXCEPTION HANDLING TEST")
print("=" * 60)

# --- 6. TEST EXCEPTION LOGGING ---
def divide_by_zero():
    """Function that raises ZeroDivisionError"""
    return 10 / 0

def file_not_found():
    """Function that raises FileNotFoundError"""
    with open("/nonexistent/file.txt", "r") as f:
        return f.read()

def type_error_example():
    """Function that raises TypeError"""
    return "string" + 123

# Test exceptions with proper logging
try:
    logger.info("Attempting division by zero...")
    result = divide_by_zero()
except ZeroDivisionError as e:
    logger.error(f"❌ ERROR: ZeroDivisionError occurred - {str(e)}")
    logger.error(f"Traceback:\n{traceback.format_exc()}")

try:
    logger.info("Attempting to read nonexistent file...")
    content = file_not_found()
except FileNotFoundError as e:
    logger.error(f"❌ ERROR: FileNotFoundError - {str(e)}")
    logger.error(f"Traceback:\n{traceback.format_exc()}")

try:
    logger.info("Attempting invalid type operation...")
    result = type_error_example()
except TypeError as e:
    logger.error(f"❌ ERROR: TypeError - {str(e)}")
    logger.error(f"Traceback:\n{traceback.format_exc()}")

print("\n" + "=" * 60)
print("📊 METRIC LOGGING TEST")
print("=" * 60)

# --- 7. LOG SOME METRICS (to test metric logging) ---
logger.info("Logging training metrics...")

# Simulate 5 training epochs
for epoch in range(1, 6):
    train_loss = 2.5 / epoch  # Decreasing loss
    val_loss = 2.3 / epoch
    accuracy = min(0.5 + (epoch * 0.1), 0.95)
    
    logger.info(f"Epoch {epoch}/5 - train_loss: {train_loss:.4f}, val_loss: {val_loss:.4f}, accuracy: {accuracy:.2%}")
    
    # Log as metrics too (if you want to test metric endpoint)
    # Note: This requires integration with TrackingClient
    # from pck67_pkg import TrackingClient
    # client = TrackingClient(api_key=os.getenv("TRACKING_API_KEY"))
    # run = client.get_run(run_id)  # You'd need run_id here
    # run.log_metric("train_loss", train_loss, step=epoch)
    # run.log_metric("val_loss", val_loss, step=epoch)
    # run.log_metric("accuracy", accuracy, step=epoch)

print("\n" + "=" * 60)
print("🎨 EDGE CASES TEST")
print("=" * 60)

# --- 8. TEST EDGE CASES ---
logger.debug("Testing very long message: " + "A" * 500)
logger.info("Testing Unicode: 🚀 🎉 🔥 ✨ 💻 🐍 📊 ⚡")
logger.warning("Testing multiline message:\nLine 1\nLine 2\nLine 3")
logger.error("Testing special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?")

# Test with different data types
logger.info(f"Testing dict: {{'model': 'ResNet50', 'accuracy': 0.95}}")
logger.info(f"Testing list: {[1, 2, 3, 4, 5]}")
logger.info(f"Testing numpy: {np.array([1.5, 2.5, 3.5])}")

print("\n" + "=" * 60)
print("✅ COMPREHENSIVE TEST COMPLETED!")
print("=" * 60)
print("\n📝 Summary:")
print("  - DEBUG messages: 3")
print("  - INFO messages: 15+")
print("  - WARNING messages: 4")
print("  - ERROR messages: 6")
print("  - CRITICAL messages: 3")
print("  - Exception tests: 3 (ZeroDivision, FileNotFound, TypeError)")
print("  - Edge cases: Unicode, long messages, special chars")
print("\n🔍 Check your tracking dashboard to verify all logs appeared!")
print("=" * 60)