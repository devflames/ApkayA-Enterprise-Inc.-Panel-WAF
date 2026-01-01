"""
ApkayA Enterprise Control Panel - Pytest Configuration
Handling 'class' keyword module imports

Copyright (c) 2025-2026 Albert Camings
Developed by: Albert Camings (Full Stack Developer)
License: MIT License - Open Source
"""

import sys
import os
import importlib

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Create module aliases to work around 'class' keyword issue
def setup_class_module_aliases():
    """Set up aliases for panel.class.* modules"""
    panel_path = os.path.join(project_root, 'panel')
    class_path = os.path.join(panel_path, 'class')
    
    # Import panel package
    spec = importlib.util.spec_from_file_location(
        'panel', 
        os.path.join(panel_path, '__init__.py')
    )
    panel_module = importlib.util.module_from_spec(spec)
    sys.modules['panel'] = panel_module
    
    # Create panel.cls as alias for panel/class
    sys.modules['panel.cls'] = type(sys)('panel.cls')
    
    # Import each module from panel/class
    if os.path.exists(class_path):
        for filename in os.listdir(class_path):
            if filename.endswith('.py') and filename != '__init__.py':
                module_name = filename[:-3]
                full_path = os.path.join(class_path, filename)
                
                try:
                    spec = importlib.util.spec_from_file_location(
                        f'panel.cls.{module_name}',
                        full_path
                    )
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        sys.modules[f'panel.cls.{module_name}'] = module
                        spec.loader.exec_module(module)
                        setattr(sys.modules['panel.cls'], module_name, module)
                except Exception as e:
                    print(f"Warning: Could not import {module_name}: {e}")

# Run setup
setup_class_module_aliases()
