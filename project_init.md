프로젝트: 도메인 & NetUtils 모니터링 에이전트

1. 개요

이 프로젝트의 목적은 다수의 도메인을 관리하는 데브옵스 엔지니어 및 시스템 관리자를 위한 포괄적인 '도메인 & 네트워크 유틸리티 모니터링 툴'을 개발하는 것입니다. 사용자는 domains.yaml 또는 domains.json 형태의 매니페스트 파일을 통해 모니터링할 도메인 목록을 정의합니다.

본 툴은 이 목록을 읽어들여 각 도메인의 ▲WHOIS 만료 정보, ▲SSL 인증서 유효 기간, ▲기본 HTTP 상태뿐만 아니라, ▲고급 DNS 레코드 상태, ▲글로벌 DNS 전파 현황, ▲필수 보안 레코드(SPF, DMARC 등) 누락 여부, ▲RBL(스팸) 등재 여부까지 한 번에 진단하고 리포트합니다.

2. 핵심 문제 (Core Problem)

수동 관리의 비효율: 여러 프로젝트에서 수십 개의 도메인을 소유할 때, 각 도메인의 만료일, SSL 인증서 만료일을 수동으로 추적하기 어렵고 실수가 발생하기 쉽습니다.

DNS 변경 확인의 어려움: DNS 레코드 변경 시, 글로벌 전파(propagation) 상태를 확인하거나 로컬 DNS 캐시와 실제 Public DNS 간의 차이를 파악하기 번거롭습니다.

파편화된 보안 점검: 도메인 운영에 필수적인 보안 레코드(SPF, DKIM, DMARC)나 DNSSEC 설정 여부, 스팸 블랙리스트(RBL) 등재 여부를 확인하기 위해 여러 툴을 전전해야 합니다.

3. 목표 (Objectives)

매니페스트 파일 기반으로 도메인 모니터링을 자동화합니다.

도메인 상태, 만료일, DNS, 보안 상태를 한눈에 볼 수 있는 통합 리포트를 제공합니다.

만료 임박, 보안 취약점 발견 시 사전 알림 (콘솔 경고) 기능을 제공합니다.

고급 DNS 진단 기능을 제공하여 트러블슈팅을 지원합니다.

4. 핵심 기능 (Key Features)

A. 기본 도메인 & SSL 모니터링

매니페스트 파싱: domains.yaml 또는 domains.json 파일을 읽어 모니터링 대상을 확정합니다. (하단 '입력 포맷' 참고)

WHOIS 정보 조회:

도메인 등록자 (Registrar)

도메인 상태 (예: clientTransferProhibited)

도메인 만료일 (경고 임계값 설정, 예: 30일 이내 만료 시 [RED])

SSL 인증서 검증:

https://(domain) (443 포트) 접속 시도

인증서 발급자 (Issuer)

주체 (Subject, SANs 포함)

SSL 인증서 만료일 (경고 임계값 설정, 예: 14일 이내 만료 시 [YELLOW])

HTTP/S 상태 코드 확인:

루트 URL (/)에 HTTP GET 요청

최종 상태 코드 반환 (예: 200, 301, 404, 503)

(선택) 리다이렉트 체인 추적 (예: http:// -> https:// -> https://www.)

B. 고급 DNS & 네트워크 진단

필수 DNS 레코드 조회:

A / AAAA

CNAME (존재 시)

MX (레코드 및 우선순위)

NS (네임서버 목록)

루트 TXT 레코드

글로벌 DNS 전파 확인:

사용자의 로컬 리졸버 외에, 지정된 여러 Public DNS 서버에 병렬로 쿼리하여 결과를 비교합니다.

대상 서버 예: Google (8.8.8.8), Cloudflare (1.1.1.1), Quad9 (9.9.9.9), 그리고 주요 지역별 DNS (예: KT, SKT DNS)

결과가 불일치할 경우 [WARNING: Propagation Mismatch] 알림

로컬 vs. Public DNS 비교:

시스템의 기본 리졸버(로컬 캐시 영향)를 사용한 nslookup 결과와 Public DNS (8.8.8.8)의 결과를 비교하여 캐시 문제로 인한 불일치를 진단합니다.

C. 보안 & 평판 감사

보안 레코드 검사:

SPF: TXT 레코드에 v=spf1 ... 존재 여부 및 기본 문법 유효성(예: +all 사용 경고) 검사

DMARC: _dmarc.{domain} TXT 레코드 존재 여부 및 p=(policy) 태그 확인

DKIM: 지정된 셀렉터(예: google._domainkey) 또는 공통 셀렉터의 CNAME/TXT 레코드 존재 여부 확인 (매니페스트에서 셀렉터 지정 가능)

DNSSEC: DS 또는 DNSKEY 레코드 존재 여부로 활성화 상태 확인

RBL (스팸 블랙리스트) 조회:

도메인 자체 및 MX 레코드의 IP 주소를 조회하여, 주요 RBL(예: Spamhaus, Barracuda) 등재 여부를 확인합니다.

HTTP 보안 헤더 검사: (추가 제안 기능)

웹사이트 응답 헤더에서 필수 보안 헤더 존재 여부 확인

Strict-Transport-Security (HSTS)

Content-Security-Policy (CSP)

X-Frame-Options

X-Content-Type-Options

D. 리포팅 및 실행

병렬 실행: 모든 도메인과 모든 검사 항목은 asyncio 등을 활용하여 최대한 병렬로 실행되어야 빠른 결과를 얻을 수 있습니다.

테이블 기반 리포트: (사용자 선호) 모든 결과를 rich 또는 tabulate 라이브러리를 사용하여 보기 쉬운 테이블 형태로 CLI에 출력합니다.

상태 하이라이팅:

정상: [GREEN] (예: OK, Expires in 300 days)

경고: [YELLOW] (예: SSL Expires in 10 days, Missing SPF)

위험: [RED] (예: EXPIRED, RBL Listed, HTTP 503)

출력 포맷: (선택) 결과를 json 또는 csv 파일로 저장하는 옵션 (-o output.json)을 제공합니다.

5. 입력 포맷 (YAML/JSON 예시)

domains.yaml (YAML 형식을 권장하나 JSON도 지원)

# 도메인별로 수행할 검사 항목을 지정할 수 있습니다.
# 생략 시 'default_checks'에 정의된 기본 검사를 수행합니다.
default_checks: [whois, ssl, http, dns, security]

domains:
  - name: "my-main-project.com"
    tags: ["prod", "main"]
    # 이 도메인은 모든 검사 + RBL 검사 + DKIM 셀렉터 'google' 검사
    checks: [whois, ssl, http, dns, security, rbl]
    dkim_selectors: ["google", "mailgun"]

  - name: "staging-project-b.net"
    tags: ["staging"]
    # 이 도메인은 SSL과 HTTP 상태만 확인
    checks: [ssl, http]

  - name: "archived-project-c.org"
    tags: ["archived"]
    # 이 도메인은 만료일만 확인
    checks: [whois]

  - name: "email-server.io"
    tags: ["prod", "infra"]
    # 이 도메인은 DNS와 보안 레코드만 집중적으로 확인
    checks: [dns, security, rbl]
    dkim_selectors: ["default"]


6. 출력 포맷 (콘솔 예시)

Domain & NetUtils Report (Total: 4)

| Domain                  | Tags         | HTTP | SSL Expiry        | WHOIS Expiry      | Security Issues                           | RBL Status |
|-------------------------|--------------|------|-------------------|-------------------|-------------------------------------------|------------|
| my-main-project.com     | prod, main   | 200  | 85 days (Green)   | 310 days (Green)  | [Y] Missing DMARC                         | OK (Green) |
| staging-project-b.net   | staging      | 200  | 40 days (Green)   | N/A               | N/A                                       | N/A        |
| archived-project-c.org  | archived     | N/A  | N/A               | 5 days (RED)      | N/A                                       | N/A        |
| email-server.io         | prod, infra  | N/A  | N/A               | 150 days (Green)  | [Y] Missing SPF, [Y] Missing DKIM(default)| LISTED (RED)|


7. 제안 기술 스택 (Python)

언어: Python 3.10+

핵심 라이브러리:

asyncio, aiohttp: 병렬/비동기 처리를 위해 (필수)

dnspython: 모든 DNS 관련 조회 (검증된 라이브러리)

python-whois: WHOIS 정보 조회 (검증된 라이브러리)

pyOpenSSL (또는 내장 ssl): SSL 인증서 상세 정보 파싱

requests (또는 aiohttp): HTTP/S 상태 코드 및 헤더 조회

PyYAML: domains.yaml 파싱

rich 또는 tabulate: CLI 테이블 출력을 위해 (가독성)

CLI 프레임워크: click 또는 argparse (표준 라이브러리)

로깅: logging (표준 라이브러리, 파일 저장 및 레벨 관리)

8. 아키텍처 제안

CLI Entrypoint (main.py): click을 사용하여 커맨드라인 인자(예: -f <file>, -d <domain>)를 파싱합니다.

Config Loader (config.py): YAML/JSON 파일을 로드하고 유효성을 검사합니다.

Checkers (패키지 checkers/): 각 기능을 모듈화합니다.

checkers/base_checker.py: (Abstract) 비동기 검사기 기본 클래스

checkers/whois.py

checkers/ssl.py

checkers/dns.py (DNS 레코드, 전파, 비교 기능 포함)

checkers/security.py (보안 레코드, RBL, 헤더 검사 포함)

Executor (executor.py): asyncio.gather를 사용하여 설정된 모든 도메인의 모든 검사를 병렬로 실행하고 결과를 취합합니다.

Reporter (reporter.py): 취합된 결과를 rich 테이블, JSON, CSV 등 요청된 포맷으로 변환하여 출력합니다.

오류 처리: 각 검사기는 try...except 구문을 통해 네트워크 오류, 타임아웃, 파싱 오류 등을 견고하게 처리하고, 리포트에 'ERROR' 상태를 반환해야 합니다.