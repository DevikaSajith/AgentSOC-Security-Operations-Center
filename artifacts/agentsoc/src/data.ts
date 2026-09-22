export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type IncidentStatus = 'Investigating' | 'Awaiting approval' | 'Contained' | 'Resolved';

export type Incident = {
  id: string; title: string; severity: Severity; source: string; resource: string;
  currentAgent: string; status: IncidentStatus; created: string; description: string;
  confidence: number; sourceIp: string; user: string;
};
export type SecurityEvent = { id: string; timestamp: string; type: string; user: string; sourceIp: string; resource: string; risk: Severity };
export type Agent = { id: string; name: string; status: 'Active' | 'Standby' | 'Paused'; purpose: string; tools: string[]; tasks: number; lastActivity: string; input: string; output: string };
export type Approval = { id: string; action: string; resource: string; reason: string; requestedBy: string; risk: Severity; incidentId: string; status: 'Pending' | 'Approved' | 'Rejected' };
export type CloudResource = { category: string; name: string; detail: string; status: 'Healthy' | 'At risk' | 'Exposed' | 'Isolated' };
export type AuditEntry = { timestamp: string; agent: string; action: string; decision: string; result: string; incidentId: string; input: string; reason: string; confidence: number };

export const seedIncidents: Incident[] = [
  { id:'INC-001', title:'IAM Privilege Escalation via Policy Attachment', severity:'critical', source:'GuardDuty', resource:'arn:aws:iam::4821:user/ci-deploy', currentAgent:'Response Agent', status:'Awaiting approval', created:'2025-02-14 14:32:18', description:'A non-admin CI principal attached AdministratorAccess to its own identity following a suspicious AssumeRole chain.', confidence:98, sourceIp:'185.41.72.19', user:'ci-deploy' },
  { id:'INC-002', title:'Public S3 Bucket Exposure Detected', severity:'high', source:'Config', resource:'s3://acme-prod-exports', currentAgent:'Validation Agent', status:'Investigating', created:'2025-02-14 14:25:06', description:'Bucket policy permits public read access and contains 4.8 GB of customer export artifacts.', confidence:94, sourceIp:'52.94.18.204', user:'data-pipeline' },
  { id:'INC-003', title:'EC2 Instance Beaconing to Known C2', severity:'high', source:'VPC Flow Logs', resource:'i-0a73c9f8d2e1b4a9c', currentAgent:'Investigation Agent', status:'Contained', created:'2025-02-14 13:58:44', description:'Outbound traffic from a production workload matches a known command-and-control fingerprint over an uncommon TLS port.', confidence:89, sourceIp:'10.42.7.18', user:'ec2-role-prod' },
  { id:'INC-004', title:'Credential Misuse from Impossible Travel', severity:'medium', source:'CloudTrail', resource:'arn:aws:iam::4821:user/m.ortiz', currentAgent:'Triage Agent', status:'Investigating', created:'2025-02-14 13:41:22', description:'The same session token was used from Singapore and Toronto within a 19 minute window.', confidence:86, sourceIp:'103.21.244.19', user:'m.ortiz' },
];
export const seedEvents: SecurityEvent[] = [
  { id:'EVT-88291', timestamp:'14:32:18.441', type:'AttachUserPolicy', user:'ci-deploy', sourceIp:'185.41.72.19', resource:'AdministratorAccess', risk:'critical' },
  { id:'EVT-88290', timestamp:'14:31:57.032', type:'AssumeRole', user:'ci-deploy', sourceIp:'185.41.72.19', resource:'arn:aws:iam::4821:role/DeployRunner', risk:'high' },
  { id:'EVT-88288', timestamp:'14:28:09.912', type:'PutBucketPolicy', user:'data-pipeline', sourceIp:'52.94.18.204', resource:'acme-prod-exports', risk:'high' },
  { id:'EVT-88284', timestamp:'14:15:40.884', type:'NetworkConnection', user:'ec2-role-prod', sourceIp:'10.42.7.18', resource:'45.83.64.12:8443', risk:'high' },
  { id:'EVT-88280', timestamp:'14:02:12.340', type:'ConsoleLogin', user:'m.ortiz', sourceIp:'103.21.244.19', resource:'us-east-1', risk:'medium' },
  { id:'EVT-88279', timestamp:'13:43:01.124', type:'GetObject', user:'data-pipeline', sourceIp:'52.94.18.204', resource:'s3://acme-prod-exports', risk:'medium' },
  { id:'EVT-88271', timestamp:'13:21:11.742', type:'AuthorizeSecurityGroupIngress', user:'ops-breakglass', sourceIp:'10.42.2.7', resource:'sg-0f1724e1', risk:'low' },
];
export const seedAgents: Agent[] = [
  { id:'detector', name:'Detection Agent', status:'Active', purpose:'Normalizes signals from cloud telemetry and identifies anomalous behavior.', tools:['GuardDuty','CloudTrail','VPC Flow Logs'], tasks:1284, lastActivity:'14 sec ago', input:'Raw cloud events', output:'Signal + confidence score' },
  { id:'triage', name:'Triage Agent', status:'Active', purpose:'Correlates events, deduplicates noise, and prioritizes incidents for analyst review.', tools:['Event correlation','Asset graph','Risk model'], tasks:247, lastActivity:'32 sec ago', input:'Detection signals', output:'Incident + severity' },
  { id:'investigation', name:'Investigation Agent', status:'Active', purpose:'Builds the attack story from identity, network, and workload evidence.', tools:['CloudTrail Lake','Threat intel','IAM graph'], tasks:94, lastActivity:'1 min ago', input:'Prioritized incident', output:'Timeline + root cause' },
  { id:'validation', name:'Validation Agent', status:'Standby', purpose:'Tests hypotheses against the simulated AWS environment before any response.', tools:['AWS Config','Policy simulator','Asset inventory'], tasks:63, lastActivity:'4 min ago', input:'Investigation findings', output:'Validated verdict' },
  { id:'response', name:'Response Agent', status:'Active', purpose:'Proposes and executes reversible containment with human approval gates.', tools:['Step Functions','SSM Run Command','IAM'], tasks:41, lastActivity:'2 min ago', input:'Validated verdict', output:'Action plan + evidence' },
];
export const seedApprovals: Approval[] = [
  { id:'APR-029', action:'Detach AdministratorAccess policy', resource:'ci-deploy', reason:'Reverse unauthorized privilege escalation and invalidate active sessions.', requestedBy:'Response Agent', risk:'critical', incidentId:'INC-001', status:'Pending' },
  { id:'APR-028', action:'Block public access', resource:'acme-prod-exports', reason:'Remove public read ACL and enforce bucket-level public access block.', requestedBy:'Response Agent', risk:'high', incidentId:'INC-002', status:'Pending' },
  { id:'APR-027', action:'Isolate EC2 instance', resource:'i-0a73c9f8d2e1b4a9c', reason:'Apply quarantine security group while preserving forensic volume state.', requestedBy:'Response Agent', risk:'high', incidentId:'INC-003', status:'Approved' },
];
export const seedResources: CloudResource[] = [
  { category:'IAM', name:'ci-deploy', detail:'User · 4 policies · us-east-1', status:'At risk' },
  { category:'S3', name:'acme-prod-exports', detail:'Bucket · 4.8 GB · us-east-1', status:'Exposed' },
  { category:'EC2', name:'i-0a73c9f8d2e1b4a9c', detail:'m6i.2xlarge · prod-vpc · 10.42.7.18', status:'Isolated' },
  { category:'RDS', name:'ledger-primary', detail:'PostgreSQL 15 · encrypted · Multi-AZ', status:'Healthy' },
  { category:'Lambda', name:'export-scheduler', detail:'Node.js 20 · 12 invocations/min', status:'Healthy' },
  { category:'VPC', name:'prod-vpc / sg-0f1724e1', detail:'3 subnets · 18 resources · us-east-1', status:'Healthy' },
];
export const seedAudit: AuditEntry[] = [
  { timestamp:'2025-02-14 14:34:03', agent:'Response Agent', action:'Propose IAM policy detach', decision:'Escalated', result:'Awaiting human approval', incidentId:'INC-001', input:'Validated privilege escalation', reason:'Reversible containment requires analyst confirmation', confidence:97 },
  { timestamp:'2025-02-14 14:33:11', agent:'Validation Agent', action:'Validate policy graph', decision:'Confirmed', result:'Escalated to response', incidentId:'INC-001', input:'AdministratorAccess attachment', reason:'Principal had no prior admin grants', confidence:99 },
  { timestamp:'2025-02-14 14:29:45', agent:'Investigation Agent', action:'Enumerate bucket exposure', decision:'Confirmed', result:'Public read confirmed', incidentId:'INC-002', input:'Config compliance finding', reason:'Anonymous GetObject succeeded in simulation', confidence:94 },
  { timestamp:'2025-02-14 14:17:02', agent:'Response Agent', action:'Apply quarantine SG', decision:'Approved', result:'Instance isolated', incidentId:'INC-003', input:'C2 beacon confidence 89%', reason:'Containment completed within 12 seconds', confidence:89 },
  { timestamp:'2025-02-14 14:03:26', agent:'Triage Agent', action:'Correlate impossible travel', decision:'Prioritized', result:'Investigation started', incidentId:'INC-004', input:'2 console sessions', reason:'Geo velocity exceeds expected user profile', confidence:86 },
];