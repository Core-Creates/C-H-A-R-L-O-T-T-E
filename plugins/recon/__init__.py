# ******************************************************************************************
# plugins/__init__.py - CHARLOTTE Plugins Package Marker
# plugins/recon/__init__.py - Package marker for recon plugins
# ******************************************************************************************

# PURPOSE:
# Marks the `plugins` directory as a Python package so imports like
# `plugins.recon.nmap.nmap_plugin` resolve correctly. This file can also
# hold shared plugin utilities in the future.
# ******************************************************************************************


__all__ = [
"nmap",
"amass",
"subdomain_enum",
]


RECON_PLUGIN_PKG_VERSION = "0.1.0"