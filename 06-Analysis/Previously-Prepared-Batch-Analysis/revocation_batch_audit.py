import zipfile,json,csv,collections,os
base='/mnt/data'; target='lab-srv-03.corp.michaelwaterman.nl';rows=[];details=[]
for archive in ['Evidence-Chrome.zip','Evidence-Edge.zip']:
 with zipfile.ZipFile(os.path.join(base,archive)) as z:
  for fn in z.namelist():
   if not fn.endswith('.json'):continue
   try: data=json.loads(z.read(fn)); ev=data['events'];typ={v:k for k,v in data['constants']['logEventTypes'].items()}
   except Exception:continue
   scen=os.path.basename(fn)[:-5];sources=collections.defaultdict(list)
   for e in ev:sources[(e['source']['type'],e['source']['id'])].append(e)
   jobs=[];requests=[];ssl=[];edges=[]
   for (st,sid),events in sources.items():
    names=[typ.get(e['type'],'') for e in events]
    if 'CERT_VERIFIER_JOB' in names:
     begins=[e for e in events if typ.get(e['type'])=='CERT_VERIFIER_JOB' and e.get('phase')==1];ends=[e for e in events if typ.get(e['type'])=='CERT_VERIFIER_JOB' and e.get('phase')==2]
     for b in begins:
      p=b.get('params',{}); certs=p.get('certificates',[]);host=p.get('host','')
      if not host and certs:
       from cryptography import x509
       try:
        c=x509.load_pem_x509_certificate(certs[0].encode()); ext=c.extensions.get_extension_for_class(x509.SubjectAlternativeName);host=','.join(ext.value.get_values_for_type(x509.DNSName))
       except Exception:pass
      if target in host:
       end=next((x for x in ends if int(x['time'])>=int(b['time'])),None);pp=end.get('params',{}) if end else {}
       jobs.append({'source':sid,'host':host,'error':pp.get('net_error',''),'status':pp.get('cert_status',''),'completed':bool(end),'time':b['time']})
    for e in events:
     name=typ.get(e['type'],'');p=e.get('params',{})
     if isinstance(p,dict):
      dep=p.get('source_dependency')
      if isinstance(dep,dict):edges.append((str(sid),str(dep.get('id')),name))
    if 'URL_REQUEST_START_JOB' in names:
     starts=[e for e in events if typ.get(e['type'])=='URL_REQUEST_START_JOB']
     for e in starts:
      url=e.get('params',{}).get('url','')
      if target in url:
       relevant=[(typ.get(x['type'],''),x.get('params',{}),x.get('phase')) for x in events]
       err=[(n,p) for n,p,ph in relevant if ('ERROR' in n or 'FAILED' in n or 'CANCELLED' in n) or (isinstance(p,dict) and p.get('net_error') not in (None,0))]
       requests.append({'source':sid,'url':url,'ssl_error_event':any(n=='URL_REQUEST_DELEGATE_SSL_CERTIFICATE_ERROR' for n,p,ph in relevant),'errors':str(err)[:350], 'events':len(events)})
    if 'SSL_CONNECT' in names:
     for e in events:
      if typ.get(e['type'])=='SSL_CONNECT':ssl.append({'source':sid,'phase':e.get('phase'),'params':str(e.get('params',{}))[:180]})
   ids={str(x['source']) for x in jobs};rids={str(x['source']) for x in requests}
   # undirected connectivity among NetLog source dependencies
   graph=collections.defaultdict(set)
   for a,b,n in edges:
    if b not in ('None',''):graph[a].add(b);graph[b].add(a)
   linked=[]
   for job in jobs:
    q=collections.deque([(str(job['source']),0)]);seen=set();found=[]
    while q:
     node,depth=q.popleft()
     if node in seen or depth>12:continue
     seen.add(node)
     if node in rids:found.append(node)
     for nxt in graph[node]:q.append((nxt,depth+1))
    linked.append({'job':job['source'],'requests':found})
   row={'archive':archive,'scenario':scen,'target_verifier_jobs':len(jobs),'verifier_errors':';'.join(str(j['error']) for j in jobs),'target_url_requests':len(requests),'target_url_ssl_error_events':sum(x['ssl_error_event'] for x in requests),'dependency_edges':len(edges),'verifier_to_request_linked':sum(bool(x['requests']) for x in linked),'target_request_error_details':' | '.join(x['errors'] for x in requests)[:500]}
   rows.append(row);details.append({'scenario':scen,'jobs':jobs,'requests':requests,'linked':linked})
with open(base+'/RevocationGap_Browser_Navigation_Audit_v11.csv','w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
with open(base+'/RevocationGap_Browser_Navigation_Details_v11.json','w') as f:json.dump(details,f,indent=2)
print('files',len(rows),'target jobs',sum(int(r['target_verifier_jobs']) for r in rows),'requests',sum(int(r['target_url_requests']) for r in rows),'ssl error requests',sum(int(r['target_url_ssl_error_events']) for r in rows),'dependency links',sum(int(r['verifier_to_request_linked']) for r in rows))
for r in rows:
 if any(s in r['scenario'] for s in ['Revoke','HttpFresh','HttpExpired']):print(r['scenario'],r['verifier_errors'],r['target_url_requests'],r['target_url_ssl_error_events'],r['verifier_to_request_linked'])
