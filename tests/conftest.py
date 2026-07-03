"""Pytest-wide isolation from the development MongoDB database.

This module is loaded before test modules import the application settings.
Database-backed tests therefore receive a dedicated database by default, while
the current browser tests continue to use their in-memory repositories.
"""

import os


os.environ["APP_ENV"] = "testing"
os.environ["MONGODB_DATABASE"] = "nepshield_test"
