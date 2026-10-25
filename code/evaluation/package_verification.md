# Independent package verification

The packaged solution was extracted into a newly allocated temporary directory. The participant dataset was copied separately and was not present in code.zip. The extracted code/main.py ran with no existing OCR cache and extracted all 11 images using Windows.Media.Ocr.

The generated output contained all 518 requested rows and matched the working output.csv byte for byte. SHA-256: b0906fe5c2fd980b91d9d2a1181bd2ffc294fd2d32f4a31a2098920fac5fbfec. Output schema, operations/states, ordering, and citation cutoffs passed validation; no authorized request had an empty step array. ZIP CRC and excluded-directory checks passed, and both required archive-root evaluation report paths were present.

The verification used Python 3 with pypdf 6.10.0, which satisfies code/requirements.txt, and built-in Windows OCR. It ran in a fresh workspace with the documented dependencies already available in the interpreter. It does not claim an offline installation test, a fresh operating system, or hidden-answer correctness. Reproduce with python code/evaluation/verify_package.py after python code/package.py.

The final package is rebuilt after adding this verification record. Source/report correspondence and ZIP integrity are checked again after that rebuild. Public expected-answer matching remains 29/32 statuses and 8/32 exact rows; see evaluation_report.md and code/BLOCKERS.md.
