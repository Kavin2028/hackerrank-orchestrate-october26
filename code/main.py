"""Evidence-driven deletion audit. No expected outputs are read by this module."""
from __future__ import annotations
import argparse
import csv
import json
import re
import sqlite3
import subprocess
import sys
import hashlib
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OP_GROUPS = [
    ['REPORT_REMAINING_RECORD','REPORT_EXPOSED_PII','REPORT_ACTIVE_DATA_FLOW','REPORT_RESTORE_RISK'],
    ['DISABLE_DATA_FLOW','BLOCK_RESTORE','DELETE_RECORD','REDACT_RECORD','ANONYMIZE_RECORD'],
    ['VERIFY_RECORD_ABSENT','VERIFY_RECORD_PRESENT','VERIFY_RECORD_REDACTED','VERIFY_RECORD_ANONYMIZED','VERIFY_DATA_FLOW_DISABLED','VERIFY_RESTORE_BLOCKED']]
PHASES = ['FINDING','REMEDIATION','VERIFICATION']
STATES = dict(zip(sum(OP_GROUPS, []), ['PRESENT','PRESENT','ACTIVE','ACTIVE','DISABLED','BLOCKED','ABSENT','REDACTED','ANONYMIZED','ABSENT','PRESENT','REDACTED','ANONYMIZED','DISABLED','BLOCKED']))
RESOURCE = re.compile(r'\b(?:account|analytics|audit_record|backup|data_flow|search|support|export|marketing|tombstone|object|cache|email_delivery|legal_hold|telemetry|secondary_identifier)_\d+\b', re.I)
KV = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s]+))')
TIME = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ')
SYSTEMS = {'account':'account_service','analytics':'analytics_platform','audit_record':'security_service','backup':'backup_service','data_flow':'integration_service','search':'search_service','support':'support_platform','export':'export_service','marketing':'marketing_platform','tombstone':'identity_service','object':'object_storage','cache':'cache_service','email_delivery':'email_delivery_service'}
CATEGORIES = {'account':'USER_PROFILE','analytics':'ANALYTICS_PROFILE','audit_record':'SECURITY_AUDIT_LOG','backup':'BACKUP_ARCHIVE','data_flow':'DATA_FLOW','search':'SEARCH_INDEX_ENTRY','support':'SUPPORT_MESSAGE','export':'USER_EXPORT','marketing':'MARKETING_PROFILE','tombstone':'ACCOUNT_TOMBSTONE','object':'SUPPORT_ATTACHMENT','cache':'CACHE_ENTRY','email_delivery':'EMAIL_DELIVERY_LOG'}
SYSTEMS.update(legal_hold='legal_service',telemetry='telemetry_service',secondary_identifier='identity_service')
CATEGORIES.update(legal_hold='LEGAL_HOLD_RECORD',telemetry='PRODUCT_TELEMETRY',secondary_identifier='SECONDARY_IDENTIFIER')
TABLE_CATEGORIES = {
    'customer_profiles':'USER_PROFILE','customer_search_documents':'SEARCH_INDEX_ENTRY',
    'customer_analytics_profiles':'ANALYTICS_PROFILE','support_records':'SUPPORT_MESSAGE',
    'customer_exports':'USER_EXPORT','connector_subscriptions':'DATA_FLOW',
    'backup_restore_entries':'BACKUP_ARCHIVE','security_audit_records':'SECURITY_AUDIT_LOG',
    'customer_analytics_reports':'ANALYTICS_PROFILE','security_audit_events':'SECURITY_AUDIT_LOG',
    'deleted_customer_references':'ACCOUNT_TOMBSTONE'}

def copy_scope(scope):
    """Unqualified service readbacks address the primary, never all replicas."""
    if not scope or scope in TABLE_CATEGORIES or scope.endswith('_primary'): return 'primary'
    if 'replica' in scope or scope in ('primary','replica'): return scope
    return 'primary'

def related_resources(content):
    if isinstance(content,dict):
        for key,value in content.items():
            if key in ('source_resource_id','parent_resource_id','account_resource_id') and isinstance(value,str):
                yield value
            elif isinstance(value,(dict,list)): yield from related_resources(value)
    elif isinstance(content,list):
        for value in content: yield from related_resources(value)

def has_reference(text,reference):
    pattern=re.escape(reference).replace('_',r'[_ ]')
    return bool(re.search(r'(?<!\w)'+pattern+r'(?!\w)',text,re.I))

def rows(path):
    with Path(path).open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))

def prefix(rid):
    return rid.rsplit('_',1)[0]

def flat_values(obj):
    if isinstance(obj, dict):
        for value in obj.values(): yield from flat_values(value)
    elif isinstance(obj, list):
        for value in obj: yield from flat_values(value)
    elif obj is not None: yield str(obj)

def truth(value):
    return str(value).lower() in ('true','1','yes','enabled','allowed')

def pii(obj, stable=False):
    """Inspect content fields, never lookup keys or resource metadata."""
    if isinstance(obj,list): return any(pii(value,stable) for value in obj)
    if not isinstance(obj, dict): return False
    for key, value in obj.items():
        if value in (None, '', '[REDACTED]', 'null', 'None'): continue
        if isinstance(value, (dict,list)) and pii(value, stable): return True
        if key in ('user_id','customer_reference','subject_reference'):
            if stable: return True
        elif any(s in key for s in ('email','phone','name')) and key not in ('event_name','connector_name','index_name','collection_name','file_name'):
            return True
        elif key in ('message_text','message_excerpt','body','subject_selector'):
            if re.search(r'[\w.+-]+@[\w.-]+|\+\d[\d -]{6,}|\buser_\d+\b', str(value)): return True
    return False

def authorizes(text):
    text = text.casefold()
    if re.search(r'ne (?:supprimez|fermez|effacez) pas|no (?:elimines|borres|cierre)|não (?:apague|exclua|elimine)|nicht (?:löschen|schließen)|削除しない|삭제하지',text): return False
    if re.search(r"not a request to (?:erase|delete)|not asking for deletion|don[’']t delete|do not (?:delete|erase|remove|close)|without (?:removing|deleting)|keep (?:the|my) account|leave the account active|information request", text): return False
    if re.search(r'promotional emails|mailing list|marketing lists? only|unsubscribe|marketing opt.out',text) and not re.search(r'(?:delete|erase|close|remove) (?:my |the |this )?account',text): return False
    return bool(re.search(r'delet|eras|remov|clos(?:e|ed|ing)|elimin|suppr|exclus|削除|삭제|حذف|löschen|apagar|profile is gone|cannot identify me', text))

@dataclass
class Observation:
    resource: str
    system: str
    category: str
    state: str
    at: str
    available: str
    evidence: str
    content: object
    scope: str = ''

class Auditor:
    def __init__(self, dataset, ocr_cache=None):
        self.dataset = Path(dataset)
        self.users = rows(self.dataset/'user_identities.csv')
        self.history = rows(self.dataset/'user_audit_log.csv')
        self.activities = rows(self.dataset/'system_activity.csv')
        self.rules = {r['data_category']:r['required_action'] for r in rows(self.dataset/'deletion_rules.csv')}
        self.policy_rows = rows(self.dataset/'deletion_rules.csv')
        self.alias = defaultdict(set)
        self.alias_available = defaultdict(dict)
        self.observations = []
        self.scopes = []
        self.diagnostics = []
        self.case_proofs={}
        self.ocr_hits=0; self.ocr_calls=0
        self.ocr_cache = ocr_cache or ROOT/'tmp'/'ocr'
        for user in self.users:
            for key in ('user_id','name','email','phone','email_hash'):
                if user.get(key):
                    alias=user[key].casefold(); uid=user['user_id']
                    self.alias[uid].add(alias)
                    self.alias_available[alias][uid]='' if key=='user_id' else user['updated_at']
        for h in self.history:
            for key in ('old_value','new_value'):
                if h.get(key):
                    alias=h[key].casefold(); uid=h['user_id']
                    self.alias[uid].add(alias)
                    self.alias_available[alias][uid]=min(self.alias_available[alias].get(uid,h['event_time']),h['event_time'])
        self.alias_index = defaultdict(set)
        for uid, aliases in self.alias.items():
            for alias in aliases:
                if len(alias)>3: self.alias_index[alias].add(uid)
        self.load_evidence()
        self._subjects={id(o):self.match(o.content) for o in self.observations}
        self._activity_subjects={id(a):self.match(a['details']) for a in self.activities}

    def match(self, content, cutoff=None):
        values = tuple(flat_values(content))
        if not hasattr(self,'_match_cache'): self._match_cache={}
        if values in self._match_cache:
            return {uid for uid,at in self._match_cache[values].items() if cutoff is None or at<=cutoff}
        known = {}
        for value in values:
            value = value.casefold()
            candidates={value}
            # Exact token matches prevent matching a related name or email prefix.
            for token in re.findall(r'[\w.+-]+@[\w.-]+|\buser_\d+\b|\b[a-f0-9]{64}\b', value):
                candidates.add(token)
            for alias in candidates:
                for uid in self.alias_index.get(alias,()):
                    at=self.alias_available[alias].get(uid,'') if hasattr(self,'alias_available') else ''
                    known[uid]=min(known.get(uid,at),at)
        self._match_cache[values]=known
        return {uid for uid,at in known.items() if cutoff is None or at<=cutoff}

    def add(self, rid, system, category, state, at, manifest, content, scope=''):
        if not rid: return
        self.observations.append(Observation(rid,system or SYSTEMS.get(prefix(rid),''),category or CATEGORIES.get(prefix(rid),''),state,at or manifest['captured_at'],manifest['captured_at'],manifest['file_id'],content,scope))

    def structured(self, record, system, collection, at, m, scope=''):
        rid = record.get('resource_id','')
        if not rid: return
        cat = record.get('record_type') or CATEGORIES.get(prefix(rid),'')
        system = record.get('system',system)
        state = record.get('result','')
        if state:
            state = {'NOT_FOUND':'ABSENT','FOUND':'PRESENT','IDENTIFIABLE':'PRESENT'}.get(state,state)
        elif cat == 'DATA_FLOW': state = 'ACTIVE' if truth(record.get('enabled')) else 'DISABLED'
        elif cat == 'BACKUP_ARCHIVE': state = 'ACTIVE' if truth(record.get('restore_allowed',record.get('restore_access',True))) else 'BLOCKED'
        elif record.get('status_code') == 404 or record.get('available') is False: state='ABSENT'
        elif cat in ('ANALYTICS_PROFILE','PRODUCT_TELEMETRY'): state='PRESENT' if pii(record,True) else 'ANONYMIZED'
        elif cat in ('SUPPORT_MESSAGE','ACCOUNT_TOMBSTONE','EMAIL_DELIVERY_LOG'): state='PRESENT' if pii(record) else 'REDACTED'
        else: state='PRESENT'
        self.add(rid,system,cat,state,record.get('observed_at',record.get('recorded_at',at)),m,record,scope)

    def load_json(self, path, m):
        data=json.loads(path.read_text(encoding='utf-8'))
        if 'snapshots' in data:
            for snap in data['snapshots']:
                at=snap['captured_at']; system=snap['data_store']; collection=snap['collection']
                present=set()
                for record in snap['records']:
                    self.structured(record,system,collection,at,m,collection); present.add(record['resource_id'])
                self.scopes.append((system,collection,at,m,present))
        elif 'service_exports' in data:
            for system, groups in data['service_exports'].items():
                for collection, records in groups.items():
                    for record in records: self.structured(record,system,collection,data['exported_at'],m)
        else:
            for record in data.get('records',[]):
                self.structured(record,'',data.get('collection',''),data.get('captured_at',data.get('exported_at')),m)

    def load_sql(self,path,m):
        conn=sqlite3.connect(':memory:'); conn.row_factory=sqlite3.Row
        conn.executescript(path.read_text(encoding='utf-8'))
        names=[r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in names:
            if table=='snapshot_scope': continue
            table_rows=[dict(r) for r in conn.execute('SELECT * FROM "'+table.replace('"','""')+'"')]
            systems=defaultdict(set)
            for r in table_rows:
                if 'resource_id' not in r: continue
                rid=r['resource_id']; system=r.get('origin_system',SYSTEMS.get(prefix(rid),''))
                record=json.loads(r['record_json']) if 'record_json' in r else r
                self.structured(record,system,r.get('collection_name',table),m['captured_at'],m,table)
                systems[system].add(rid)
            # SQL is a complete table snapshot. Missing rows prove absence only in
            # this table; another replica can still contain the same resource.
            if table.startswith('customer_data_'):
                possible=set(r.get('origin_system','') for r in table_rows)
            else:
                possible=set(systems)
                if table.startswith('customer_profiles'): possible.add('account_service')
                if table=='customer_search_documents': possible.add('search_service')
                if table in TABLE_CATEGORIES:
                    cat=TABLE_CATEGORIES[table]
                    possible.update(SYSTEMS[p] for p,c in CATEGORIES.items() if c==cat)
            for system in possible:
                self.scopes.append((system,table,m['captured_at'],m,systems[system]))
        conn.close()

    def load_log(self,path,m):
        traces={}
        for line in path.read_text(encoding='utf-8').splitlines():
            times=TIME.findall(line)
            if not times: continue
            at=times[0]
            if '{' in line:
                try: d=json.loads(line[line.index('{'):])
                except ValueError: d={k:a or b for k,a,b in KV.findall(line)}
            else: d={k:a or b for k,a,b in KV.findall(line)}
            # Normalize syslog, application, pipe, and cloud runtime envelopes.
            app=re.search(r'\[\w+\] \[([^]]+)\] \[([^]]+)\] (\w+):',line)
            pipe=re.search(r'\| \w+ \| ([^|]+) \| ([^|]+) \| (\w+) \|',line)
            syslog=re.search(r'<\d+>1 \S+ (\S+) (\S+) - -',line)
            if app: d.update(service=app[1],trace_id=app[2],event=app[3])
            if pipe: d.update(service=pipe[1].strip(),trace_id=pipe[2].strip(),event=pipe[3])
            if syslog: d.update(service=syslog[1],trace_id=syslog[2])
            if 'function' in d:
                message=re.search(r'message="(.*)"$',line)
                if message: d.update({k:a or b for k,a,b in KV.findall(message[1].replace('\\"','"'))})
                d['service']=d['function']; d['trace_id']=d.get('requestId','')
            trace=d.get('trace_id',d.get('trace',''))
            if trace:
                traces.setdefault(trace,{}).update(d)
                d=traces[trace].copy()
            rid=d.get('resource_id','')
            if not rid: continue
            event=d.get('event','')
            if event=='record_lookup':
                self.structured(d,d.get('system',''),'',at,m); continue
            if not re.search('lookup_completed|query_completed|readback|read_completed|pii_scan|identity_scan|heartbeat|candidate_evaluated',event): continue
            p=prefix(rid); state=None
            if 'result' in d and d['result'] in ('hit','miss'): state='PRESENT' if d['result']=='hit' else 'ABSENT'
            if 'rows' in d: state='ABSENT' if str(d['rows'])=='0' else 'PRESENT'
            if p=='data_flow': state='ACTIVE' if truth(d.get('enabled')) else 'DISABLED'
            if p=='backup':
                if 'restore_allowed' in d: state='ACTIVE' if truth(d['restore_allowed']) else 'BLOCKED'
                elif 'eligible' in d: state='ACTIVE' if truth(d['eligible']) and not truth(d.get('deletion_block',False)) else 'BLOCKED'
            if p=='analytics': state='PRESENT' if pii(d,True) else 'ANONYMIZED'
            if event=='analytics_identity_scan': state='PRESENT' if truth(d.get('identifiable',d.get('direct_identifier_present',True))) else 'ANONYMIZED'
            if p=='support':
                fields={k:v for k,v in d.items() if k.startswith('requester_') or k=='message_text'}
                state='PRESENT' if pii(fields) or 'pii_scan' in event or ('contact_query' in event and state=='PRESENT') else 'REDACTED'
            if p=='export' and 'available' in d: state='PRESENT' if truth(d['available']) else 'ABSENT'
            if p=='audit_record' and state is None and d.get('integrity_check')=='passed': state='PRESENT'
            cat=CATEGORIES.get(p,'')
            if 'attachment' in event: cat='SUPPORT_ATTACHMENT'
            if 'contact_lookup' in event or 'contact_query' in event: cat='SECONDARY_IDENTIFIER'
            scope=d.get('pool','') if 'replica' in d.get('pool','') else ''
            if state: self.add(rid,SYSTEMS.get(p,''),cat,state,at,m,d,scope)

    def load_text(self,text,m):
        for line in text.splitlines():
            parts=[p.strip() for p in line.lstrip('- ').split('|')]
            if len(parts)>=6 and TIME.fullmatch(parts[0]):
                at,system,rid,cat,state,subject=parts[:6]
                self.add(rid,system,cat,{'NOT_FOUND':'ABSENT','FOUND':'PRESENT','IDENTIFIABLE':'PRESENT'}.get(state,state),at,m,{'subject_reference':subject})

    def load_image(self,path,m):
        # Cache by content so another dataset with the same filenames cannot
        # reuse an unrelated extraction.
        cache=self.ocr_cache/(path.stem+'-'+hashlib.sha256(path.read_bytes()).hexdigest()[:16]+'.txt')
        if not cache.exists():
            self.ocr_calls+=1
            self.ocr_cache.mkdir(parents=True,exist_ok=True)
            if sys.platform=='win32':
                proc=subprocess.run(['powershell','-NoProfile','-ExecutionPolicy','Bypass','-File',str(Path(__file__).with_name('ocr.ps1')),'-ImagePath',str(path.resolve())],capture_output=True,encoding='utf-8')
                if proc.returncode: raise RuntimeError(proc.stderr)
                cache.write_text(proc.stdout,encoding='utf-8')
            else:
                proc=subprocess.run(['tesseract',str(path),'stdout'],capture_output=True,text=True,check=True)
                cache.write_text(proc.stdout,encoding='utf-8')
        else:
            self.ocr_hits+=1
        text=cache.read_text(encoding='utf-8-sig')
        # OCR is a content observation; nearby business artifacts can contain
        # unrelated customers. Identity matching happens later.
        rids=set(RESOURCE.findall(text))
        for rid in rids:
            p=prefix(rid); cat=CATEGORIES.get(p,'')
            state='PRESENT'
            if p=='data_flow': state='DISABLED' if re.search(r'\bdisabled\b',text,re.I) else 'ACTIVE'
            if p=='backup': state='BLOCKED' if re.search(r'restore (?:blocked|disabled)',text,re.I) else 'ACTIVE'
            if p=='tombstone': state='PRESENT' if re.search(r'[\w.+-]+@[\w.-]+',text) else 'REDACTED'
            # Detail panels follow the selected resource in these business UIs.
            # Do not attach every customer in a visible results table to it.
            local=text[text.rfind(rid):]
            self.add(rid,SYSTEMS.get(p,''),cat,state,m['captured_at'],m,{'ocr':local})
        # Reference registry screens expose a stable user key instead of the
        # catalog resource ID. Use catalog links, never invented resource IDs.
        for a in self.activities:
            if a['event_type']!='LINK_RESOURCE_IDENTITY': continue
            rid=a['resource_id']; p=prefix(rid)
            aliases=re.findall(r'\(([^)]+)\)',a['details'])
            # The identity link is filtered at audit time, independently from
            # the captured object's presence. Do not use it as a state claim.
            if any(has_reference(text,alias) for alias in aliases) and rid not in rids:
                state='REDACTED' if p=='tombstone' and not re.search(r'[\w.+-]+@[\w.-]+',text) else 'PRESENT'
                linked_manifest=dict(m,captured_at=max(m['captured_at'],a['event_time']))
                self.add(rid,a['target_system'],CATEGORIES.get(p,''),state,m['captured_at'],linked_manifest,{'ocr':text})

    def load_pdf(self,path,m):
        from pypdf import PdfReader
        text='\n'.join(p.extract_text(extraction_mode='layout') for p in PdfReader(path).pages)
        self.load_text(text,m)
        # Documents without structured rows: resource identifiers and business
        # contents form evidence of a record, not a pre-written verdict.
        for rid in set(RESOURCE.findall(text)):
            if any(o.evidence==m['file_id'] and o.resource==rid for o in self.observations): continue
            cat=CATEGORIES.get(prefix(rid),'')
            if prefix(rid)=='support' and re.search(r'attachment|uploader customer',text,re.I): cat='SUPPORT_ATTACHMENT'
            self.add(rid,SYSTEMS.get(prefix(rid),''),cat,'PRESENT',m['captured_at'],m,{'document':text})
        for a in self.activities:
            if a['event_type']=='LINK_RESOURCE_IDENTITY':
                names=re.findall(r'\(([^)]+)\)',a['details'])
                if any(has_reference(text,n) for n in names if not re.fullmatch(r'user_\d+',n)) and not any(o.evidence==m['file_id'] and o.resource==a['resource_id'] for o in self.observations):
                    linked_manifest=dict(m,captured_at=max(m['captured_at'],a['event_time']))
                    rid=a['resource_id']; self.add(rid,a['target_system'],CATEGORIES.get(prefix(rid),''),'PRESENT',m['captured_at'],linked_manifest,{'document':text})

    def load_evidence(self):
        for m in rows(self.dataset/'evidence_files.csv'):
            path=self.dataset/m['file_path']
            suffix=path.suffix.lower()
            if suffix=='.json': self.load_json(path,m)
            elif suffix=='.sql': self.load_sql(path,m)
            elif suffix=='.log': self.load_log(path,m)
            elif suffix=='.txt': self.load_text(path.read_text(encoding='utf-8'),m)
            elif suffix=='.pdf': self.load_pdf(path,m)
            elif suffix in ('.png','.jpg','.jpeg'): self.load_image(path,m)
            else: raise ValueError('Unsupported evidence format: '+str(path))

    def audit(self,request):
        if not authorizes(request['request_text']): return {'case_id':request['case_id'],'deletion_status':'NOT_APPLICABLE','steps_json':'[]'}
        cutoff=request['audit_at']
        users=self.match(request['email'],cutoff)
        if len(users)!=1: raise ValueError('Ambiguous or unresolved identity: '+request['case_id'])
        uid=next(iter(users))
        available=[o for o in self.observations if o.available<=cutoff and o.at<=cutoff]
        membership=defaultdict(set)
        for o in available:
            people=self.match(o.content,cutoff)
            membership[o.resource].update(people)
            for linked in related_resources(o.content): membership[linked].update(people)
        for a in self.activities:
            if a['event_time']<=cutoff:
                membership[a['resource_id']].update(self.match(a['details'],cutoff))
        relevant={rid for rid,people in membership.items() if uid in people}
        artifact_subjects=defaultdict(set)
        for o in available:
            artifact_subjects[o.evidence].update(membership[o.resource])
        # Strongly scoped readback evidence can establish absence of a resource
        # observed earlier. Absent SQL rows do not imply absence in a replica.
        selected=defaultdict(list)
        for o in available:
            if o.resource in relevant: selected[o.resource].append(o)
        for system,scope,at,m,present in self.scopes:
            if at>cutoff or m['captured_at']>cutoff: continue
            # Inventory exports can cover a batch of subjects rather than the
            # entire platform. A different batch cannot erase earlier records.
            if uid not in artifact_subjects[m['file_id']]: continue
            for rid in relevant:
                if rid in present or SYSTEMS.get(prefix(rid))!=system: continue
                existing=selected.get(rid,[])
                # Only absence from the same semantic collection/table counts.
                cat=TABLE_CATEGORIES.get(scope)
                if scope.startswith('customer_profiles'): cat='USER_PROFILE'
                same_collection=cat==CATEGORIES.get(prefix(rid)) or scope.startswith('customer_data_')
                if same_collection or any(o.scope==scope and o.system==system and o.at<=at for o in existing):
                    selected[rid].append(Observation(rid,system,CATEGORIES.get(prefix(rid),''),'ABSENT',at,m['captured_at'],m['file_id'],{},scope))
        final=[]
        for rid,items in selected.items():
            copies=defaultdict(list)
            for o in items: copies[(o.system,copy_scope(o.scope))].append(o)
            current=[]
            for observations in copies.values():
                latest=max(o.at for o in observations)
                choices=[o for o in observations if o.at==latest]
                choices.sort(key=lambda o:(o.state not in ('PRESENT','ACTIVE'),o.evidence))
                current.append(choices[0])
            # Any independently evidenced noncompliant physical copy defeats
            # compliance of another copy, even when the latter is newer.
            current.sort(key=lambda o:(o.state not in ('PRESENT','ACTIVE'),-len(o.at),o.evidence))
            violations=[o for o in current if o.state in ('PRESENT','ACTIVE')]
            final.append(max(violations or current,key=lambda o:(o.at,o.evidence)))
        finding=[]; remediation=[]; verification=[]
        missing=relevant-set(selected)
        unresolved=bool(missing)
        for rid in sorted(missing): self.diagnostics.append(request['case_id']+': linked resource has no state evidence: '+rid)
        def step(o,op,evidence=''):
            return {'step_no':0,'phase':PHASES[next(i for i,g in enumerate(OP_GROUPS) if op in g)],'system_id':o.system,'resource_id':o.resource,'operation':op,'state':STATES[op],'evidence_id':evidence}
        for o in final:
            action=self.rules.get(o.category,'DISABLE' if o.category=='DATA_FLOW' else None)
            if not action:
                self.diagnostics.append('No policy for '+o.resource); unresolved=True; continue
            content=o.content if isinstance(o.content,dict) else {}
            if action=='RETAIN' and o.category=='SECURITY_AUDIT_LOG' and content.get('retention_until','9999')<cutoff:
                # No supplied rule mandates erasure after retention expires.
                # Do not invent one or falsely assert an absent record exists.
                if o.state=='ABSENT': continue
            if action=='RETAIN' and o.category=='LEGAL_HOLD_RECORD' and content.get('hold_active') is False:
                if o.state=='ABSENT': continue
            if o.category=='DATA_FLOW':
                bad=o.state=='ACTIVE'; report='REPORT_ACTIVE_DATA_FLOW'; fix='DISABLE_DATA_FLOW'; verify='VERIFY_DATA_FLOW_DISABLED'
            elif o.category=='BACKUP_ARCHIVE':
                bad=o.state=='ACTIVE'; report='REPORT_RESTORE_RISK'; fix='BLOCK_RESTORE'; verify='VERIFY_RESTORE_BLOCKED'
            elif action=='DELETE':
                bad=o.state!='ABSENT'; report='REPORT_REMAINING_RECORD'; fix='DELETE_RECORD'; verify='VERIFY_RECORD_ABSENT'
            elif action in ('REDACT','ANONYMIZE'):
                if o.state=='ABSENT':
                    if action=='ANONYMIZE':
                        verification.append(step(o,'VERIFY_RECORD_ABSENT',o.evidence)); continue
                    unresolved=True
                    self.diagnostics.append(request['case_id']+': required shared record/tombstone absent: '+o.resource+'; no permitted recovery operation')
                    verification.append(step(o,'VERIFY_RECORD_PRESENT')); continue
                target='REDACTED' if action=='REDACT' else 'ANONYMIZED'
                bad=o.state!=target; report='REPORT_EXPOSED_PII'; fix=action+'_RECORD'; verify='VERIFY_RECORD_'+target
            else:
                bad=o.state=='ABSENT'; report=None; fix=None; verify='VERIFY_RECORD_PRESENT'
                if bad:
                    unresolved=True
                    self.diagnostics.append('Required retained record absent: '+o.resource+'; allowed operations do not express recovery')
                    # Future presence is a required check, not a claim that
                    # this absent observation proves presence now.
            if bad and report:
                finding.append(step(o,report,o.evidence)); remediation.append(step(o,fix))
            verification.append(step(o,verify,o.evidence))
        # Missing evidence cannot establish COMPLETE. The contract has no UNKNOWN
        # status; conservatively mark this as incomplete and flag manual review.
        incomplete=bool(finding) or not final or unresolved
        if not final: self.diagnostics.append('No linked state evidence for '+request['case_id'])
        if hasattr(self,'case_proofs'):
            self.case_proofs[request['case_id']]=final
        if incomplete:
            for s in verification: s['evidence_id']=''
        all_steps=finding+remediation+verification
        all_steps.sort(key=lambda s:(PHASES.index(s['phase']),OP_GROUPS[PHASES.index(s['phase'])].index(s['operation']),s['system_id'],s['resource_id']))
        for i,s in enumerate(all_steps,1): s['step_no']=i
        return {'case_id':request['case_id'],'deletion_status':'INCOMPLETE' if incomplete else 'COMPLETE','steps_json':json.dumps(all_steps,ensure_ascii=False,separators=(',',':'))}

    def run(self,requests):
        return [self.audit(r) for r in sorted(requests,key=lambda r:r['case_id'])]

def write_output(path,predictions):
    with Path(path).open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['case_id','deletion_status','steps_json']); writer.writeheader(); writer.writerows(predictions)

def main():
    p=argparse.ArgumentParser(); p.add_argument('--dataset',type=Path,default=ROOT/'dataset'); p.add_argument('--requests',default='deletion_requests.csv'); p.add_argument('--output',type=Path,default=ROOT/'output.csv')
    args=p.parse_args(); auditor=Auditor(args.dataset); predictions=auditor.run(rows(args.dataset/args.requests)); write_output(args.output,predictions)
    print(f'Wrote {len(predictions)} rows to {args.output}')
    print(json.dumps({'status_counts':dict(__import__('collections').Counter(r['deletion_status'] for r in predictions)),'diagnostics':auditor.diagnostics},ensure_ascii=False))

if __name__=='__main__': main()
