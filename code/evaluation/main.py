"""Evaluate public samples and write transparent, reproducible reports."""
import sys
import json
import subprocess
import time
from collections import Counter
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from main import ROOT, Auditor, rows, write_output, OP_GROUPS, PHASES, STATES

def validate(predictions, requests, dataset):
    errors=[]; review=[]
    ids=[r['case_id'] for r in predictions]
    if ids!=sorted(r['case_id'] for r in requests): errors.append('Case coverage or order mismatch')
    evidence={r['file_id']:r['captured_at'] for r in rows(dataset/'evidence_files.csv')}
    evidence.update({r['activity_id']:r['event_time'] for r in rows(dataset/'system_activity.csv')})
    evidence.update({r['audit_id']:r['event_time'] for r in rows(dataset/'user_audit_log.csv')})
    by_id={r['case_id']:r for r in requests}
    fields={'step_no','phase','system_id','resource_id','operation','state','evidence_id'}
    for row in predictions:
        cid=row['case_id']; status=row['deletion_status']; steps=json.loads(row['steps_json'])
        if status not in ('COMPLETE','INCOMPLETE','NOT_APPLICABLE'): errors.append(cid+': invalid status')
        if status=='NOT_APPLICABLE' and steps: errors.append(cid+': unauthorized steps')
        if status!='NOT_APPLICABLE' and not steps: review.append(cid+': no linked state evidence; conservative INCOMPLETE without an inventable resource plan')
        previous=None
        for n,s in enumerate(steps,1):
            if set(s)!=fields or s['step_no']!=n: errors.append(cid+': schema/numbering')
            if s['operation'] not in STATES or s['state']!=STATES.get(s['operation']): errors.append(cid+': operation/state')
            phase=PHASES.index(s['phase']); key=(phase,OP_GROUPS[phase].index(s['operation']),s['system_id'],s['resource_id'])
            if previous is not None and previous>key: errors.append(cid+': ordering')
            previous=key
            needs_evidence=s['phase']=='FINDING' or status=='COMPLETE'
            if needs_evidence and (s['evidence_id'] not in evidence or evidence[s['evidence_id']]>by_id[cid]['audit_at']): errors.append(cid+': invalid or future evidence')
            if not needs_evidence and s['evidence_id']: errors.append(cid+': future action citation')
            if status=='COMPLETE' and s['phase']!='VERIFICATION': errors.append(cid+': complete case has actions')
    return errors,review

def main():
    start=time.perf_counter(); a=Auditor(ROOT/'dataset')
    requests=rows(ROOT/'dataset/deletion_requests.csv'); full=a.run(requests); write_output(ROOT/'output.csv',full)
    elapsed=time.perf_counter()-start
    full_diagnostics=list(a.diagnostics); a.diagnostics=[]
    sample=a.run(rows(ROOT/'dataset/sample_deletion_requests.csv'))
    expected={r['case_id']:r for r in rows(ROOT/'dataset/sample_output.csv')}
    statuses=exact=sequence=0; correct_fields=field_total=matched=pred_steps=gold_steps=0; failures=[]
    for r in sample:
        e=expected[r['case_id']]; actual=json.loads(r['steps_json']); gold=json.loads(e['steps_json'])
        status_ok=r['deletion_status']==e['deletion_status']; statuses+=status_ok
        exact+=status_ok and actual==gold; sequence+=actual==gold
        aa={json.dumps(s,sort_keys=True) for s in actual}; bb={json.dumps(s,sort_keys=True) for s in gold}
        matched+=len(aa&bb); pred_steps+=len(actual); gold_steps+=len(gold)
        for i in range(max(len(actual),len(gold))):
            for key in ('step_no','phase','system_id','resource_id','operation','state','evidence_id'):
                field_total+=1
                correct_fields+=i<len(actual) and i<len(gold) and actual[i][key]==gold[i][key]
        if actual!=gold or not status_ok:
            failures.append(f"- {r['case_id']}: status {'correct' if status_ok else 'incorrect'}; predicted {len(actual)} steps, expected {len(gold)}; exact-step matches {len(aa&bb)}.")
    errors,review=validate(full,requests,ROOT/'dataset')
    result=subprocess.run([sys.executable,'-m','unittest','discover','-s',str(Path(__file__).parent),'-p','test_*.py','-v'],capture_output=True,text=True)
    report=f'''# Evaluation report

## Reproduction

Run `python code/evaluation/main.py` from the repository root. This runs the full dataset, evaluates the 32 public samples, validates the submission contract, and runs six independent synthetic tests. Public expected outputs are read only here, never by the predictor. Hidden answer accuracy is unknown.

## Measured public-sample results

- Status accuracy: {statuses}/32 ({statuses/32:.2%}).
- Exact row accuracy (status and entire JSON sequence): {exact}/32 ({exact/32:.2%}).
- Sequence accuracy (entire ordered JSON array): {sequence}/32 ({sequence/32:.2%}).
- Step precision (including step numbers): {matched}/{pred_steps} ({matched/max(pred_steps,1):.2%}).
- Step recall: {matched}/{gold_steps} ({matched/max(gold_steps,1):.2%}).
- Positional field accuracy across seven fields, counting missing/extra fields as wrong: {correct_fields}/{field_total} ({correct_fields/max(field_total,1):.2%}).

## Full-run validation

- Requests: {len(requests)}; generated rows: {len(full)}.
- Status counts: {dict(Counter(r['deletion_status'] for r in full))}.
- Structural/schema, operation/state, evidence-cutoff, and ordering errors: {len(errors)}.
- Rows requiring manual evidence review: {len(review)}.
- End-to-end run time with existing OCR cache: {elapsed:.2f} seconds.
- Synthetic regression suite exit code: {result.returncode}.

## Independent evaluation cases

1. A data-access request explicitly prohibiting deletion yields NOT_APPLICABLE and no actions.
2. A successful deletion observation after audit_at cannot override an earlier present record.
3. A historical email resolves the subject while a required security record is preserved.
4. A replica containing a profile defeats an absent primary at the same snapshot time.
5. A tombstone may keep its stable reference but must remove direct identifiers and email hashes.
6. Restore blocking must precede record deletion; future actions have blank evidence IDs.

## Failures and improvements

Initial parsing missed syslog, pipe, cloud, and application log envelopes. The parser now normalizes each, correlates traces, and recognizes readback, PII scans, heartbeat, and restore checks. It distinguishes support attachments and secondary contact indexes from shared support messages. Screenshot parsing scopes identifiers to detail panels to reduce unrelated-customer matches. Multilingual deletion requests and explicit non-deletion requests are handled separately.

Exact step coverage remains incomplete. In particular, absent or fully anonymized records can have no recoverable subject link in evidence available before the cutoff. The implementation does not invent identifiers or copy canonical answers to fill these gaps. Some selected records may still be associated too broadly in complex business artifacts. Cases without any linked state evidence are conservatively INCOMPLETE with an empty step array, flagged for manual review; their missing resource plan means they do not fully satisfy the semantic output contract. Policy application is deterministic by category; complex retention conditions and cross-source conflicts need further semantic review. This is a runnable baseline, not a claim of hidden-test correctness or a fully verified deletion audit.

### Public sample mismatches

{chr(10).join(failures) or 'None.'}

### Full-run evidence review

{chr(10).join('- '+x for x in review+full_diagnostics) or 'None.'}

### Validation errors

{chr(10).join('- '+x for x in errors) or 'None.'}

### Synthetic test output

```text
{result.stdout}{result.stderr}
```
'''
    (Path(__file__).parent/'evaluation_report.md').write_text(report,encoding='utf-8')
    usage=f'''# Final full-dataset usage report

The final run processed {len(requests)} requests and generated root-level output.csv in {elapsed:.2f} seconds (with cached OCR extraction).

## Models and providers

Image text extraction uses Microsoft Windows.Media.Ocr on Windows, or locally installed Tesseract on other systems. The exact proprietary Windows OCR model identifier is not exposed by the OS API. OCR is local machine learning inference; no generative model or remote provider is invoked by the audit pipeline. PDF extraction uses pypdf. Identity resolution, state reconstruction, policy application, and serialization use deterministic Python code.

## Per-model and overall accounting

- Generative model provider/name: none.
- Generative model calls: 0.
- Input tokens: 0; output tokens: 0; total tokens: 0.
- Average tokens per request: 0.
- Estimated total API cost: USD 0.00.
- Estimated API cost per request: USD 0.00.
- OCR images read from local cache on this run: {len(list((ROOT/'tmp/ocr').glob('*.txt')))}. Cache misses invoke local OCR; OCR has no token billing.
- Overall totals are identical because no paid model API is used. Local compute/electricity cost is not measured.

Development of the code used Codex (gpt-6.1-sol). Development-session token usage is separate from final pipeline inference and is not measured by this program; it is not represented as zero. No credentials are needed for the submitted pipeline.
'''
    (Path(__file__).parent/'usage_report.md').write_text(usage,encoding='utf-8')
    print(f'Public samples: status {statuses}/32; exact {exact}/32. Validation errors: {len(errors)}. Review rows: {len(review)}.')
    print(result.stderr)
    if errors or result.returncode: raise SystemExit(1)

if __name__=='__main__': main()
