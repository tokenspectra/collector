"""OpenAI Responses API scenarios for capture.py: the official OpenAI Python
SDK against mock_openai_responses.py, over HTTP/1.1 or h2c.
"""

import openai

from capture_openai import sdk

MODEL = "mock-model"
INPUT = "Say hello."


def json_calls(c):
    c.responses.create(model=MODEL, input=INPUT)
    # Cut short: status incomplete, reason max_output_tokens.
    c.responses.create(model=MODEL, input=INPUT, max_output_tokens=2, previous_response_id="resp_mock_0000")


def sse_calls(c):
    for _ in c.responses.create(model=MODEL, input=INPUT, stream=True):
        pass
    for _ in c.responses.create(model=MODEL, input=INPUT, max_output_tokens=2, stream=True):
        pass


def error_calls(c):
    # A 404 JSON error, then a stream that ends in response.failed.
    try:
        c.responses.create(model="missing-model", input=INPUT)
    except openai.NotFoundError:
        pass
    for _ in c.responses.create(model="failing-model", input=INPUT, stream=True):
        pass


def with_sdk(http2, calls):
    def run(port):
        c = sdk(port, http2)
        calls(c)
        c.close()

    return run


SCENARIOS = {
    "openai_responses_h1_json": with_sdk(False, json_calls),
    "openai_responses_h1_sse": with_sdk(False, sse_calls),
    "openai_responses_h2c_json": with_sdk(True, json_calls),
    "openai_responses_h2c_sse": with_sdk(True, sse_calls),
    "openai_responses_error_h1": with_sdk(False, error_calls),
}
