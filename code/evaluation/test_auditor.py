"""Independent synthetic cases, not challenge answer lookups."""
import sys
import unittest
from collections import defaultdict
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from main import Auditor, Observation, authorizes, pii, has_reference

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

    def test_older_replica_survives_new_primary_absence(self):
        a=self.agent([self.observation('profile','USER_PROFILE','PRESENT',scope='replica'),self.observation('profile','USER_PROFILE','ABSENT','2026-01-01T23:00:00Z',scope='primary')])
        self.assertEqual(a.audit(self.request())['deletion_status'],'INCOMPLETE')

    def test_replica_own_newer_absence_resolves_its_presence(self):
        a=self.agent([self.observation('profile','USER_PROFILE','PRESENT',scope='replica'),self.observation('profile','USER_PROFILE','ABSENT','2026-01-01T23:00:00Z',scope='replica'),self.observation('profile','USER_PROFILE','ABSENT',scope='primary')])
        self.assertEqual(a.audit(self.request())['deletion_status'],'COMPLETE')

    def test_missing_retained_record_never_proves_presence(self):
        import json
        a=self.agent([self.observation('retained','SECURITY_AUDIT_LOG','ABSENT')])
        r=a.audit(self.request())
        self.assertEqual(r['deletion_status'],'INCOMPLETE')
        self.assertTrue(a.diagnostics)
        self.assertTrue(all(s['evidence_id']=='' for s in json.loads(r['steps_json'])))

    def test_unverified_delete_claim_does_not_prove_absence(self):
        a=self.agent([])
        a.activities=[{'event_time':'2026-01-01T00:00:00Z','resource_id':'profile','details':'subject','event_type':'DELETE_RECORD','reported_result':'SUCCESS'}]
        self.assertEqual(a.audit(self.request())['deletion_status'],'INCOMPLETE')

    def test_unavailable_historical_alias_does_not_link_subject(self):
        a=self.agent([self.observation('profile','USER_PROFILE','PRESENT')])
        a.alias_available=defaultdict(dict,{'old@example.test':{'subject':'2026-01-03T00:00:00Z'},'subject':{'subject':''}})
        self.assertNotIn('subject',a.match('old@example.test','2026-01-02T00:00:00Z'))

    def test_future_capture_excluded_even_with_earlier_event(self):
        o=self.observation('profile','USER_PROFILE','ABSENT')
        o.available='2026-01-03T00:00:00Z'
        a=self.agent([o])
        self.assertEqual(a.audit(self.request())['deletion_status'],'INCOMPLETE')

    def test_unrelated_inventory_batch_cannot_clear_record(self):
        a=self.agent([self.observation('account_custom','USER_PROFILE','PRESENT',scope='customer_profiles')])
        a.observations[0].system='account_service'
        a.scopes=[('account_service','customer_profiles','2026-01-01T23:00:00Z',{'captured_at':'2026-01-01T23:00:00Z','file_id':'other_batch'},set())]
        self.assertEqual(a.audit(self.request())['deletion_status'],'INCOMPLETE')

    def test_later_catalog_link_is_not_available_earlier(self):
        a=self.agent([Observation('profile','test_system','USER_PROFILE','PRESENT','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','witness',{'email':'unrelated@example.test'})])
        a.activities=[{'event_time':'2026-01-03T00:00:00Z','resource_id':'profile','details':'subject'}]
        self.assertEqual(a.audit(self.request())['steps_json'],'[]')

    def test_nested_list_identifiers_are_not_anonymous(self):
        self.assertTrue(pii({'events':[{'email':'person@example.test'}]},True))

    def test_multilingual_non_deletion(self):
        self.assertFalse(authorizes('Ne supprimez pas mon compte.'))
        self.assertFalse(authorizes('Não apague minha conta.'))
        self.assertTrue(authorizes('Solicito la eliminación permanente de la cuenta.'))

    def test_absent_analytics_does_not_report_exposed_pii(self):
        import json
        a=self.agent([self.observation('analytics','ANALYTICS_PROFILE','ABSENT')])
        a.rules['ANALYTICS_PROFILE']='ANONYMIZE'
        r=a.audit(self.request())
        self.assertEqual(r['deletion_status'],'COMPLETE')
        self.assertEqual(json.loads(r['steps_json'])[0]['operation'],'VERIFY_RECORD_ABSENT')

    def test_document_mapping_waits_for_catalog_availability(self):
        from unittest.mock import patch, MagicMock
        a=self.agent([])
        a.activities=[{'event_time':'2026-01-03T00:00:00Z','resource_id':'profile','event_type':'LINK_RESOURCE_IDENTITY','target_system':'test_system','details':'Catalog linked profile (ABC) to subject'}]
        page=MagicMock(); page.extract_text.return_value='Statement ABC for subject'
        reader=MagicMock(); reader.pages=[page]
        with patch('pypdf.PdfReader',return_value=reader):
            a.load_pdf(Path('not-read.pdf'),{'file_id':'witness','captured_at':'2026-01-01T00:00:00Z'})
        self.assertEqual(len(a.observations),1)
        self.assertEqual(a.observations[0].available,'2026-01-03T00:00:00Z')
        self.assertEqual(a.audit(self.request())['steps_json'],'[]')

    def test_catalog_reference_requires_whole_token(self):
        self.assertFalse(has_reference('user_170','user_17'))
        self.assertTrue(has_reference('selected user 17 reference','user_17'))

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
