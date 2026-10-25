"""Independent synthetic cases, not challenge answer lookups."""
import sys
import unittest
from collections import defaultdict
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from main import Auditor, Observation, authorizes, pii

class AuditTests(unittest.TestCase):
    def agent(self, observations):
        a=Auditor.__new__(Auditor)
        a.alias_index=defaultdict(set,{'old@example.test':{'subject'},'subject':{'subject'}})
        a.activities=[]; a.scopes=[]; a.observations=observations; a.diagnostics=[]
        a.rules={'USER_PROFILE':'DELETE','ACCOUNT_TOMBSTONE':'REDACT','SECURITY_AUDIT_LOG':'RETAIN','BACKUP_ARCHIVE':'RETAIN'}
        return a

    def observation(self,rid,category,state,at='2026-01-01T00:00:00Z',scope=''):
        return Observation(rid,'test_system',category,state,at,at,'witness',{'subject_reference':'subject'},scope)

    def request(self,text='Please delete my account.'):
        return {'case_id':'synthetic','email':'old@example.test','request_text':text,'audit_at':'2026-01-02T00:00:00Z'}

    def test_non_deletion_never_authorizes_actions(self):
        a=self.agent([self.observation('profile','USER_PROFILE','PRESENT')])
        r=a.audit(self.request('Send a copy of my information; do not delete anything.'))
        self.assertEqual(r['deletion_status'],'NOT_APPLICABLE'); self.assertEqual(r['steps_json'],'[]')

    def test_future_observation_cannot_change_status(self):
        a=self.agent([self.observation('profile','USER_PROFILE','PRESENT'),self.observation('profile','USER_PROFILE','ABSENT','2026-01-03T00:00:00Z')])
        self.assertEqual(a.audit(self.request())['deletion_status'],'INCOMPLETE')

    def test_historical_email_and_retention(self):
        import json
        a=self.agent([self.observation('profile','USER_PROFILE','ABSENT'),self.observation('retained','SECURITY_AUDIT_LOG','PRESENT')])
        r=a.audit(self.request()); self.assertEqual(r['deletion_status'],'COMPLETE')
        self.assertEqual([s['operation'] for s in json.loads(r['steps_json'])],['VERIFY_RECORD_ABSENT','VERIFY_RECORD_PRESENT'])

    def test_replica_presence_overrides_primary_absence(self):
        a=self.agent([self.observation('profile','USER_PROFILE','ABSENT',scope='primary'),self.observation('profile','USER_PROFILE','PRESENT',scope='replica')])
        self.assertEqual(a.audit(self.request())['deletion_status'],'INCOMPLETE')

    def test_tombstone_keeps_stable_reference_only(self):
        self.assertFalse(pii({'subject_reference':'subject','email':None,'name':None}))
        self.assertTrue(pii({'subject_reference':'subject','email_hash':'abcdef'}))
        a=self.agent([self.observation('tombstone','ACCOUNT_TOMBSTONE','REDACTED')])
        self.assertEqual(a.audit(self.request())['deletion_status'],'COMPLETE')

    def test_restore_risk_precedes_record_removal(self):
        import json
        a=self.agent([self.observation('profile','USER_PROFILE','PRESENT'),self.observation('archive','BACKUP_ARCHIVE','ACTIVE')])
        s=json.loads(a.audit(self.request())['steps_json'])
        actions=[x for x in s if x['phase']=='REMEDIATION']
        self.assertEqual([x['operation'] for x in actions],['BLOCK_RESTORE','DELETE_RECORD'])
        self.assertTrue(all(x['evidence_id']=='' for x in s if x['phase']!='FINDING'))

if __name__=='__main__': unittest.main()
