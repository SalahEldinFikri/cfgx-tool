import importlib.util


def load_decryptor(decryptor_path):
    spec = importlib.util.spec_from_file_location(
        "cfgx_decryptor",
        decryptor_path
    )

    if spec is None:
        raise ImportError("Could not create module specification")

    if spec.loader is None:
        raise ImportError("Could not load analyst plugin")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def validate_result(result):
    
    if not isinstance(result, dict):
        raise TypeError("extract() must return a dictionary")

    if "status" not in result:
        raise ValueError("Result must contain 'status'")
    
    if not isinstance(result["status"], str):
        raise TypeError("Result 'status' must be a string")
    
    if "config" not in result:
        raise ValueError("Result must contain 'config'")

    return result