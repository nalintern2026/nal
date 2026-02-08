#!/usr/bin/env python3
"""
Project setup script for multi-system deployment.
Initializes configuration and creates necessary directories.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from nal.src.config.paths import (
    detect_system,
    setup_directories,
    get_data_path,
    get_models_path,
    get_results_path,
    get_cicids_path,
)


def main():
    """Main setup function."""
    print("=" * 60)
    print("Network Traffic Classification & Anomaly Detection")
    print("Project Setup Script")
    print("=" * 60)
    print()
    
    # Detect system
    system = detect_system()
    print(f"Detected system: {system}")
    print()
    
    # Check if config exists
    config_path = project_root / 'configs' / 'system_config.yaml'
    if not config_path.exists():
        template_path = project_root / 'configs' / 'system_config.template.yaml'
        if template_path.exists():
            print("⚠️  Configuration file not found!")
            print(f"   Please copy {template_path.name} to system_config.yaml")
            print(f"   and update the paths for your system.")
            print()
            print("   Example:")
            print(f"   cp {template_path} {config_path}")
            print()
            return
        else:
            print("❌ Configuration template not found!")
            return
    
    print("✓ Configuration file found")
    print()
    
    # Setup directories
    print("Creating/verifying directories...")
    try:
        setup_directories()
        print("✓ Directories created/verified")
    except Exception as e:
        print(f"❌ Error creating directories: {e}")
        return
    
    print()
    print("Project paths:")
    print(f"  Data:     {get_data_path()}")
    print(f"  Models:   {get_models_path()}")
    print(f"  Results:  {get_results_path()}")
    print(f"  CIC-IDS:  {get_cicids_path()}")
    print()
    
    # Check for CIC-IDS dataset
    cicids_path = Path(get_cicids_path())
    if cicids_path.exists():
        csv_files = list(cicids_path.glob("*.csv"))
        if csv_files:
            print(f"✓ Found {len(csv_files)} CIC-IDS CSV files")
            for f in csv_files:
                print(f"    - {f.name}")
        else:
            print("⚠️  CIC-IDS directory exists but no CSV files found")
            print(f"   Expected location: {cicids_path}")
    else:
        print("⚠️  CIC-IDS dataset not found")
        print(f"   Expected location: {cicids_path}")
        print("   Please place CIC-IDS 2017 dataset files here")
    
    print()
    print("=" * 60)
    print("Setup complete!")
    print()
    print("Next steps:")
    print("1. Place CIC-IDS dataset files in the CIC-IDS directory")
    print("2. Review docs/WORKFLOW_PLAN.md for development plan")
    print("3. Review docs/QUICK_START.md for getting started")
    print("=" * 60)


if __name__ == '__main__':
    main()
