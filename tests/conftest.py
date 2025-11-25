"""
Pytest configuration and path setup
Automatically adds project root to Python path for all tests
"""
import sys
import os

# Add project root to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

print(f"✅ Python path configured: {project_root}")
