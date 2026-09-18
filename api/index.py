import os
import sys

# Ensure Web_Fuzzer-main directory is in python search path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
fuzzer_dir = os.path.join(base_dir, 'Web_Fuzzer-main')
if fuzzer_dir not in sys.path:
    sys.path.insert(0, fuzzer_dir)

from web_app import app

# Handler for Vercel Serverless
app = app
