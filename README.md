# TokenSpectra Collector

The Rust Collector for [TokenSpectra](https://github.com/tokenspectra/tokenspectra). It reads network traffic from a live interface or from pcap files. It accounts for every byte, decodes LLM requests (OpenAI, Anthropic and Ollama) into Request Workunits, and stores everything under BLAKE3 hashes as evidence an auditor can check.

![The capture viewer on local Ollama traffic](docs/viewer.png)

## Quick start

You need Rust, [Ollama](https://ollama.com), Python 3, and `dumpcap` runnable without root (on Ubuntu: `sudo apt install wireshark-common`, answer **Yes** to non-superuser capture, then `sudo usermod -aG wireshark $USER`).

```sh
ollama pull qwen2.5:0.5b

# terminal 1: capture loopback in 10 s windows
sg wireshark -c "cargo run -- ring -i lo -w 10 -o ts-captures-demo"

# terminal 2: send some prompts
python3 tools/llm_traffic.py --stream --count 5 --interval 10
```

Press Ctrl-C in terminal 1, open `viewer/index.html` in a browser and choose `ts-captures-demo/`.

To read existing captures instead: `cargo run -- files -o out/ capture.pcapng`. Run the tests with `cargo test --workspace`.
