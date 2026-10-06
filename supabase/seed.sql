-- Optional non-production demo fixtures. Safe to re-run; all ids are deterministic.
insert into public.alerts (id, "timestamp", severity, source_ip, source_country, source_lat, source_lng, destination_ip, protocol, attack_type, signature, status, raw_log)
select
  'ALT-SEED-' || lpad(g.i::text, 4, '0'),
  now() - make_interval(mins => (g.i * 27) % 1440),
  case when g.i % 13 = 0 then 'critical' when g.i % 5 = 0 then 'high' when g.i % 3 = 0 then 'medium' else 'low' end,
  (array['185.220.101.45','103.74.118.23','198.98.57.12','177.54.148.77','45.155.205.233','91.240.118.172','175.45.176.14'])[((g.i * 5 + (g.i / 3)) % 7) + 1],
  (array['Russia','China','United States','Brazil','India','Iran','North Korea'])[((g.i * 5 + (g.i / 3)) % 7) + 1],
  (array[55.75,31.23,39.74,-23.55,19.08,35.69,39.02]) [((g.i * 5 + (g.i / 3)) % 7) + 1],
  (array[37.62,121.47,-104.99,-46.63,72.88,51.39,125.75]) [((g.i * 5 + (g.i / 3)) % 7) + 1],
  '10.24.' || ((g.i % 4) + 1)::text || '.' || ((g.i * 11) % 200 + 20)::text,
  (array['TCP','TCP','TCP','UDP','HTTPS','HTTP','SSH'])[(g.i % 7) + 1],
  (array['Port Scan','SSH Brute Force','SQL Injection','DDoS','Malware C2','XSS','Ransomware','Zero-Day Exploit'])[((g.i * 3 + (g.i / 4)) % 8) + 1],
  'ET ' || (array['SCAN Potential service discovery scan','POLICY SSH brute force attempt','WEB_SERVER SQL injection attempt','DOS Possible UDP amplification attack','TROJAN C2 beacon detected','WEB_CLIENT Cross-site scripting attempt','MALWARE ransomware payload delivery','EXPLOIT suspicious memory corruption pattern'])[((g.i * 3 + (g.i / 4)) % 8) + 1],
  case when g.i % 17 = 0 then 'resolved' when g.i % 11 = 0 then 'investigating' when g.i % 13 = 0 then 'blocked' else 'new' end,
  '[seed] sensor event id=' || g.i::text || ' classified by NetDefender demo fixture'
from generate_series(1, 50) as g(i)
on conflict (id) do nothing;

insert into public.blocked_ips (id, ip, reason, blocked_by, blocked_at, expires_at, is_active) values
('BLK-SEED-01','185.220.101.45','Automated SSH brute force','Alex Morgan',now()-interval '5 hours',null,true),
('BLK-SEED-02','103.74.118.23','SQL injection campaign','Maya Chen',now()-interval '7 hours',null,true),
('BLK-SEED-03','45.155.205.233','Credential stuffing source','Alex Morgan',now()-interval '10 hours',now()+interval '1 day',true),
('BLK-SEED-04','91.240.118.172','Known malicious scanner','Maya Chen',now()-interval '1 day',null,true),
('BLK-SEED-05','177.54.148.77','DDoS botnet node','Alex Morgan',now()-interval '2 days',now()-interval '1 day',false),
('BLK-SEED-06','175.45.176.14','Malware C2 beacon','Jordan Lee',now()-interval '2 days',null,true),
('BLK-SEED-07','198.98.57.12','Port scanning activity','Alex Morgan',now()-interval '3 days',now()+interval '12 hours',true),
('BLK-SEED-08','185.156.73.92','Repeated authentication failures','Maya Chen',now()-interval '4 days',now()-interval '2 days',false),
('BLK-SEED-09','89.248.165.16','Exploit probing','Alex Morgan',now()-interval '5 days',null,true),
('BLK-SEED-10','194.26.29.101','Threat intelligence match','Maya Chen',now()-interval '6 days',now()+interval '3 days',true)
on conflict (id) do nothing;

insert into public.sensors (id,name,type,ip,status,cpu,memory,uptime,last_heartbeat) values
('SNS-01','Edge Sensor · Ashburn','Suricata','10.24.1.10','online',32,68,'14d 06h 32m',now()),
('SNS-02','Core Monitor · Frankfurt','Zeek','10.24.2.14','online',24,54,'8d 19h 04m',now()),
('SNS-03','Endpoint Cluster · SFO','Wazuh','10.24.3.21','warning',82,78,'3d 12h 58m',now()-interval '1 minute'),
('SNS-04','DMZ Sensor · Singapore','Suricata','10.24.4.08','offline',0,0,'—',now()-interval '24 minutes'),
('SNS-05','Cloud Workloads · London','Zeek','10.24.5.16','online',41,61,'21d 02h 11m',now())
on conflict (id) do nothing;

insert into public.firewall_rules (id,name,action,protocol,source,destination,port,enabled,created_by,created_at) values
('FW-001','Block known threat feeds','deny','ANY','Threat Intel','0.0.0.0/0','ANY',true,'System',now()-interval '60 days'),
('FW-002','Allow HTTPS inbound','allow','TCP','0.0.0.0/0','10.24.0.0/16','443',true,'Alex Morgan',now()-interval '30 days'),
('FW-003','Restrict SSH access','deny','TCP','!10.24.0.0/16','10.24.0.0/16','22',true,'Maya Chen',now()-interval '21 days'),
('FW-004','Allow DNS egress','allow','UDP','10.24.0.0/16','1.1.1.1','53',true,'Alex Morgan',now()-interval '14 days'),
('FW-005','Block legacy SMB','deny','TCP','0.0.0.0/0','10.24.0.0/16','445',false,'Jordan Lee',now()-interval '7 days')
on conflict (id) do nothing;

insert into public.incidents (id,title,description,severity,status,assigned_to,created_at,resolved_at,notes) values
('INC-SEED-2084','Credential spray on VPN gateway','A coordinated password spray targeted the remote access gateway from residential proxy networks. No successful authentication has been confirmed.','critical','new','Maya Chen',now()-interval '36 minutes',null,'["Correlated 84 source IPs across 11 minutes.","VPN policy requires MFA on all accounts."]'::jsonb),
('INC-SEED-2083','Outbound beaconing from app tier','Repeated outbound TLS sessions to a newly registered domain were observed from the production application subnet.','high','investigating','Alex Morgan',now()-interval '142 minutes',null,'["Host isolated from internet egress.","Endpoint triage in progress."]'::jsonb),
('INC-SEED-2081','SQL injection attempt blocked','WAF prevented a UNION-based SQL injection against the customer search endpoint. No data exposure identified.','medium','resolved','Jordan Lee',now()-interval '890 minutes',now()-interval '370 minutes','["WAF signature updated.","No database anomalies found."]'::jsonb)
on conflict (id) do nothing;

insert into public.playbooks (id,name,trigger_condition,condition_json,actions_json,enabled,created_at) values
('PB-SEED-001','Auto-block critical sources','severity = critical','{"field":"severity","operator":"equals","value":"critical"}'::jsonb,'["Block IP","Create Incident"]'::jsonb,true,now()-interval '45 days'),
('PB-SEED-002','Escalate brute force','attack_type = SSH Brute Force','{"field":"attack_type","operator":"equals","value":"SSH Brute Force"}'::jsonb,'["Block IP","Send Email","Slack Notify"]'::jsonb,true,now()-interval '30 days'),
('PB-SEED-003','Triage SQL injection','attack_type = SQL Injection','{"field":"attack_type","operator":"equals","value":"SQL Injection"}'::jsonb,'["Create Incident","Slack Notify"]'::jsonb,true,now()-interval '20 days'),
('PB-SEED-004','Notify on high severity','severity = high','{"field":"severity","operator":"equals","value":"high"}'::jsonb,'["Send Email"]'::jsonb,false,now()-interval '10 days')
on conflict (id) do nothing;

-- Audit fixtures are system/demo events. User identity remains nullable so seeding never depends on
-- a real auth.users row. Metadata carries the display actor for the admin audit view.
insert into public.audit_logs (id, user_id, action, target, metadata, created_at) values
('AUD-SEED-001',null,'blocked_ip.added','185.220.101.45','{"actor":"Alex Morgan","reason":"Automated SSH brute force"}'::jsonb,now()-interval '12 minutes'),
('AUD-SEED-002',null,'incident.updated','INC-SEED-2083','{"actor":"Maya Chen","status":"investigating"}'::jsonb,now()-interval '84 minutes'),
('AUD-SEED-003',null,'firewall_rule.toggled','FW-005','{"actor":"Alex Morgan","enabled":false}'::jsonb,now()-interval '231 minutes'),
('AUD-SEED-004',null,'alert.resolved','ALT-SEED-0017','{"actor":"Jordan Lee","status":"resolved"}'::jsonb,now()-interval '427 minutes'),
('AUD-SEED-005',null,'playbook.created','PB-SEED-004','{"actor":"Maya Chen","trigger":"severity = high"}'::jsonb,now()-interval '812 minutes')
on conflict (id) do nothing;

-- Notifications are scoped to real profiles. Run this seed after at least one test user has signed up.
insert into public.notifications (id, user_id, title, message, type, read, created_at)
select 'NTF-SEED-' || p.id::text || '-' || v.event_id,
       p.id,
       v.title,
       v.message,
       v.type,
       v.is_read,
       now() - v.age
from public.profiles p
cross join (values
  ('01','Critical alert detected','Credential spray activity from 185.220.101.45','critical',false,interval '4 minutes'),
  ('02','Sensor needs attention','Endpoint Cluster · SFO is operating above 80% CPU.','warning',false,interval '26 minutes'),
  ('03','Block list synced','Threat intelligence feed sync completed successfully.','success',true,interval '74 minutes')
) as v(event_id,title,message,type,is_read,age)
on conflict (id) do nothing;

-- Promote a chosen user after signup in a trusted SQL console (replace with the operator's UUID):
-- update public.profiles set role = 'admin' where id = '00000000-0000-0000-0000-000000000000';
