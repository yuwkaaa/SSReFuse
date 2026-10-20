"""Positive control for the Python detectors.

Every detector run scans this file in the same invocation as the corpus. It is
the smallest unmistakable SSRF there is, so a configuration that reports nothing
here is broken, and a zero on the corpus from that run means "the detector did
not work", not "the corpus is clean". The runner refuses to return results when
this file comes back empty.
"""
import requests
from flask import Flask, request

app = Flask(__name__)


@app.get("/control")
def control():
    url = request.args.get("url")
    return requests.get(url).text
