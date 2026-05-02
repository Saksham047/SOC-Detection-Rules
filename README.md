# SOC-Detection-Rules

#  Detection Use Cases

## 1️. Brute Force Login Detection

###  Description
Detects multiple failed login attempts from a single IP address followed by a successful login.

###  Why it matters
This pattern indicates a brute force attack where an attacker attempts multiple passwords and eventually gains access.


## 2. Impossible Travel Detection

### Why this detection triggers
A user logging in from geographically distant locations within a short time window is not physically possible.  
This behavior typically indicates compromised credentials, session hijacking, or unauthorized access from a different region.

Such activity is commonly observed when:
- Credentials are leaked and used by attackers from another country  
- VPN/proxy-based access is used by threat actors  
- Multiple sessions are created from different regions simultaneously  

---
