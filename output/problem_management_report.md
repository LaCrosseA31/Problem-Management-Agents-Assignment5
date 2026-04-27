# FinServe Problem Management Report — Q1 2026

## Agent-Driven Analysis Results

# RFC 1: Loan-Approval Engine ERR-5012  
**Status**: Proposed Standard  
**Abstract**: This document defines a permanent fix for the recurring error ERR-5012 in the Loan-Approval Engine, caused by DB-Cluster-3 under-provisioning due to undocumented batch jobs.  

**Problem**:  
The Loan-Approval Engine intermittently fails with ERR-5012 during peak loan validation hours (10:00 UTC Wednesday). This occurs because DB-Cluster-3, which hosts two other services, lacks auto-scaling rules for the undocumented Wednesday batch job.  

**Root Cause**:  
CHG-2001 (a database resource adjustment) removed auto-scaling for the Wednesday loan validation workload. The CMDB note "batch reconciliation runs Tue 22:00 UTC" was misinterpreted as the only critical batch job, leading to under-provisioning.  

**Workaround**:  
Temporarily increase DB-Cluster-3 resources during peak hours (10:00 UTC Wednesday) and document all batch schedules in CMDB.  

**Permanent Fix**:  
Implement auto-scaling for DB-Cluster-3 based on workload patterns. Ensure all critical batch jobs are documented in CMDB with associated resource requirements.  

**Evidence**:  
- CHG-2001 (database resource adjustment)  
- CMDB note: "batch reconciliation runs Tue 22:00 UTC"  
- `query_cmdb(CI-1001)` (undocumented batch job)  

---

# RFC 2: Account-Access Service ERR-7045  
**Status**: Proposed Standard  
**Abstract**: This document addresses ERR-7045 in the Account-Access Service, caused by LB-02 misconfiguration during payroll traffic spikes.  

**Problem**:  
The Account-Access Service fails with ERR-7045 on the 15th of each month during payroll cycles. This occurs because LB-02 lacks dynamic weight distribution for traffic spikes.  

**Root Cause**:  
CHG-2005 (load balancer rule update) removed dynamic weight distribution for the 15th. The CMDB note "payroll cycles peak at 15th" was not linked to LB-02 policies, amplifying the impact on three hosted services.  

**Workaround**:  
Re-enable dynamic weight distribution on LB-02 for the 15th and manually adjust load balancer settings during payroll cycles.  

**Permanent Fix**:  
Update LB-02 to include dynamic weight distribution for traffic spikes. Link CMDB notes about payroll cycles to LB-02 policies.  

**Evidence**:  
- CHG-2005 (load balancer rule update)  
- CMDB note: "payroll cycles peak at 15th"  
- `query_cmdb(CI-1003)` (undocumented policy link)  

---

# RFC 3: Transaction-Processing ERR-9028  
**Status**: Proposed Standard  
**Abstract**: This document resolves ERR-9028 in the Transaction-Processing system, caused by certificate chain validation failures in Legacy-Auth-01.  

**Problem**:  
The Transaction-Processing system fails with ERR-9028 during certificate renewals due to expired root certificates in Legacy-Auth-01.  

**Root Cause**:  
CHG-2009 (certificate rotation) used expired root certificates from the internal CA. The risk assessment for CHG-2009 lacked certificate chain validation criteria, leading to critical failures.  

**Workaround**:  
Validate certificate chain validity for Legacy-Auth-01 and temporarily re-enable expired root certificates.  

**Permanent Fix**:  
Implement automated certificate chain validation during rotations. Ensure all certificates use valid root certificates from the internal CA.  

**Evidence**:  
- CHG-2009 (certificate rotation)  
- CMDB note: "certificate renewal failures"  
- `query_cmdb(CI-1003)` (unvalidated certificate chain)  

---

# RFC 4: Customer Portal ERR-3011  
**Status**: Proposed Standard  
**Abstract**: This document corrects ERR-3011 in the Customer Portal, caused by CDN-East misconfiguration during regional outages.  

**Problem**:  
The Customer Portal fails with ERR-3011 during regional outages due to CDN-East cache purging policies being disabled.  

**Root Cause**:  
CHG-2013 (CDN policy update) disabled cache purging during outages. The CMDB note "static asset caching during outages" was not synchronized with CDN-East policies, affecting four hosted services.  

**Workaround**:  
Re-enable cache purging policies on CDN-East during outages and manually purge caches for impacted services.  

**Permanent Fix**:  
Synchronize CDN-East policies with regional outage response plans. Document cache purging rules in CMDB and test during outage simulations.  

**Evidence**:  
- CHG-2013 (CDN policy update)  
- CMDB note: "static asset caching during outages"  
- `query_cmdb(CI-1004)` (unsynchronized outage plan)  

--- 

Each RFC provides a structured solution to the documented root causes, ensuring long-term system reliability.