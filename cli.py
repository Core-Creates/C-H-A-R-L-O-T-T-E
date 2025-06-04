from core.plugin_manager import run_plugin

task = input("What task should CHARLOTTE run? ").strip()
arg_string = input("Provide args as key=value pairs (comma separated): ").strip()

# Parse args
args = {}
if arg_string:
    for pair in arg_string.split(","):
        key, value = pair.strip().split("=")
        args[key.strip()] = value.strip()

output = run_plugin(task, args)
print("\n🔧 Plugin Output:\n", output)