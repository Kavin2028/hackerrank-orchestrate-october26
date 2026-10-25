# Final full-dataset usage report

The final run processed 518 requests and generated root-level output.csv in 1.68 seconds (with cached OCR extraction).

## Models and providers

Image text extraction uses Microsoft Windows.Media.Ocr on Windows, or locally installed Tesseract on other systems. The exact proprietary Windows OCR model identifier is not exposed by the OS API. OCR is local machine learning inference; no generative model or remote provider is invoked by the audit pipeline. PDF extraction uses pypdf. Identity resolution, state reconstruction, policy application, and serialization use deterministic Python code.

## Per-model and overall accounting

- Generative model provider/name: none.
- Generative model calls: 0.
- Input tokens: 0; output tokens: 0; total tokens: 0.
- Average tokens per request: 0.
- Estimated total API cost: USD 0.00.
- Estimated API cost per request: USD 0.00.
- OCR images read from local cache on this run: 11. Cache misses invoke local OCR; OCR has no token billing.
- Overall totals are identical because no paid model API is used. Local compute/electricity cost is not measured.

Development of the code used Codex (gpt-6.1-sol). Development-session token usage is separate from final pipeline inference and is not measured by this program; it is not represented as zero. No credentials are needed for the submitted pipeline.
