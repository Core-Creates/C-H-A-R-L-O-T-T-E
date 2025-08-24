from zapv2 import ZAPv2

zap = ZAPv2(apikey='', proxies={'http': 'http://localhost:8090', 'https': 'http://localhost:8090'})
print(zap.core.version)


def run (args):
    # The main function for the plugin.
    return "Hello World!"

