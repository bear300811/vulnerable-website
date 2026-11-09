# vulnerable-website

취약점 탐색 → 공격표면 발견 → 공격 → 검증 파이프라인을 테스트하기 위한 **의도적으로 취약한** 웹 애플리케이션입니다. 가상의 팀 파일 공유 SaaS "Hearthfile"로 구성되어 있습니다.

> ⚠️ 교육·테스트 목적 전용입니다. 외부에 배포하거나 공용 네트워크에 노출하지 마세요. 서버는 `127.0.0.1`에만 바인딩됩니다.

## 구성

- `server.js`: Node.js 서버(표준 라이브러리만 사용). API와 취약점 로직이 여기에 있습니다.
- `public/`: HTML 페이지와 프론트엔드 파일. 디자인은 `design-taste-frontend` 스킬 시스템을 따릅니다.
- `files/`, `uploads/`: 실행 중 생성되는 파일 저장소입니다.

## 실행 방법

```bash
node server.js
# http://127.0.0.1:8000
```

Node.js 22.13 이상이 필요합니다(`node:sqlite` 사용). 실행 시 SQLite 실험 경고가 출력될 수 있습니다.

## 페이지

`/` (홈), `/login.html`, `/register.html`, `/search.html`, `/reviews.html`, `/profile.html`, `/account.html`, `/admin.html`, `/tools.html`, `/upload.html`

## 취약점 목록

| # | 취약점 | 위치 (엔드포인트) | CWE / OWASP |
|---|--------|-------------------|-------------|
| 1 | SQL Injection (로그인 우회) | `POST /api/login` (`username`) | CWE-89 / A03:2021 Injection |
| 2 | 취약한 비밀번호 해싱 (MD5, 솔트 없음) | `POST /api/login` 및 DB 저장 방식 | CWE-327, CWE-916 / A02:2021 Cryptographic Failures |
| 3 | 서명되지 않은 세션 쿠키 변조 | `session` 쿠키 → `/api/admin`, `/api/account`, `/api/transfer` | CWE-565, CWE-639 / A01:2021 Broken Access Control |
| 4 | 관리자 기능 접근 제어 누락 (클라이언트 측 role 신뢰) | `GET /api/admin`, `/admin.html` | CWE-285 / A01:2021 Broken Access Control |
| 5 | Reflected XSS (DOM 기반) | `/search.html` (`q` 쿼리 파라미터) | CWE-79 / A03:2021 Injection |
| 6 | Stored XSS | `GET·POST /api/comments` → `/reviews.html` | CWE-79 / A03:2021 Injection |
| 7 | IDOR (타인 정보 조회) | `GET /api/profile` (`id`), `/profile.html` | CWE-639 / A01:2021 Broken Access Control |
| 8 | CSRF (토큰 없는 송금) | `POST /api/transfer` | CWE-352 / A01:2021 Broken Access Control |
| 9 | 비즈니스 로직 결함 (음수 송금 허용) | `POST /api/transfer` (`amount`) | CWE-840 / A04:2021 Insecure Design |
| 10 | OS Command Injection | `GET /api/ping` (`host`) | CWE-78 / A03:2021 Injection |
| 11 | Path Traversal (임의 파일 읽기) | `GET /api/file` (`name`) | CWE-22 / A01:2021 Broken Access Control |
| 12 | SSRF | `GET /api/fetch` (`url`) | CWE-918 / A10:2021 SSRF |
| 13 | Open Redirect | `GET /redirect` (`next`) | CWE-601 / A01:2021 Broken Access Control |
| 14 | 무제한 파일 업로드 (타입·이름 검증 없음, HTML 그대로 서빙) | `POST /api/upload` (`name`) → `GET /uploads/<경로>` | CWE-434, CWE-22 / A04:2021 Insecure Design |
| 15 | 민감 정보 노출 (시크릿 키, 사용자 비밀번호 해시) | `GET /api/debug` | CWE-200 / A05:2021 Security Misconfiguration |
| 16 | 상세 에러 노출 (스택 트레이스) | 모든 API의 예외 처리 (500 응답) | CWE-209 / A05:2021 Security Misconfiguration |
| 17 | 공격표면 힌트 노출 | `GET /robots.txt` (`/admin.html`, `/api/debug` 등 나열) | CWE-200 |
| 18 | 대량 할당 (회원가입 시 권한 지정) | `POST /api/register` (`role`) | CWE-915 / A01:2021 Broken Access Control |

## 공격표면 요약

- 정적 페이지: 위 페이지 목록
- API: `/api/register`, `/api/login`, `/api/search`, `/api/comments`, `/api/profile`, `/api/account`, `/api/transfer`, `/api/admin`, `/api/ping`, `/api/file`, `/api/fetch`, `/api/upload`, `/api/debug`
- 기타: `/redirect`, `/uploads/<경로>`, `/robots.txt`
- 인증: 로그인 후 `session` 쿠키(Base64 JSON, 서명 없음)로 사용자 식별

## 참고

- 취약점별 공격 페이로드와 정답은 의도적으로 README에 적지 않았습니다. 파이프라인이 직접 발견·검증해야 합니다.
- 데이터는 메모리 내 SQLite이며 서버 재시작 시 초기화됩니다.
- 경로 traversal 테스트는 클라이언트가 경로를 정규화하지 않도록 설정해야 할 수 있습니다(예: `curl --path-as-is`).
