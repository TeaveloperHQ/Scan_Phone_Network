<p align="center">
  <img src="assets/icon-256.png" width="128" height="128" alt="업무망 점검기 아이콘"/>
</p>

# 업무망 무단 장비 점검기 (Scan_Phone_Network)

학교 **업무망**에 무단으로 연결된 장비를 자동으로 찾아내는 도구입니다.

- 🔴 전화업자가 스위치/방화벽에 꽂은 **공유기(NAT 라우터)**
- 🔴 교사가 무단 설치한 **무선 AP**
- 🟡 미등록 **인터넷 전화기(VoIP)**

비전문가 교사도 더블클릭 한 번으로 점검할 수 있는 **GUI 앱**이며,
정보부장 PC에 두면 **백그라운드에서 망을 상시 감시**하고 새 무단 장비가 나타나면 경고합니다.

📖 **사용자용 설명서: [MANUAL.md](MANUAL.md)**

---

## 탐지 원리

| 신호 | 무엇을 잡나 |
|------|------------|
| MAC OUI 조회 | 제조사로 구분 (ipTIME·TP-Link=공유기 / Yealink·Cisco=전화기) |
| ICMP 핑 스윕 + TTL | 살아있는 호스트 + NAT 뒤 추가 홉 |
| SSDP/UPnP (UDP 1900) | 공유기의 `InternetGatewayDevice` 광고 → **가장 확실** |
| DHCP 서버 탐지 | 무단 공유기가 자체 DHCP 응답 → 결정적 증거 |
| SIP OPTIONS (5060) | 전화기 모델/벤더 |
| NetBIOS 이름(137) 대조 | 같은 PC 이름을 여러 장비가 사용(복제 설치) → ⚠ 이름중복 |
| HTTP 배너/타이틀 (80/443) | 공유기 로그인·전화기 관리 페이지 |

여러 신호를 합쳐 **종류 + 신뢰도(0~100%)** 로 판정합니다.

---

## 프로젝트 구조

```
Scan_Phone_Network.sln
└─ src/
   ├─ Core/   ScanPhoneNetwork.Core   엔진(스캔·프로브·분류·CSV) — net8.0
   ├─ Gui/    ScanPhoneNetwork.Gui    Avalonia 화면 + 감시 + 트레이 — net8.0
   └─ Cli/    ScanPhoneNetwork.Cli    명령줄 버전(테스트·헤드리스) — net8.0
```

> GUI는 **Avalonia UI**라 **리눅스에서 개발·실행하고 Windows exe로 배포**합니다(전 프로젝트 OS 무관).

---

## 빌드

```bash
# 전체 빌드 (Linux/Windows 공통)
dotnet build -c Release

# GUI 실행해 보기
dotnet run --project src/Gui

# 배포용 Windows 단일 실행파일(.NET 런타임 포함)
dotnet publish src/Gui/ScanPhoneNetwork.Gui.csproj -c Release -r win-x64 --self-contained
# 결과: src/Gui/bin/Release/net8.0/win-x64/publish/업무망점검기.exe
```

---

## 사용법

### GUI
1. `업무망점검기.exe` 더블클릭
2. (선택) **대상 대역**에 `10.20.30.0/24` 입력 — 비우면 PC 대역 자동
3. **스캔 시작** → 결과 표에서 빨간 행 = 의심 장비
4. **CSV 저장** → 교육청 보고/대장용
5. 의심 장비가 정상이면 우클릭 → **정상(승인) 등록**

### 감시 모드 (정보부장 PC)
1. **감시 모드** 체크 + 주기(분) 설정
2. **윈도우 시작 시 자동 실행** 체크 → 로그인 시 트레이에서 자동 감시
3. 승인 목록에 없는 새 의심 장비 발견 시 트레이 알림 + 경고음

### CLI (테스트용)
```bash
scan-phone-network 10.20.30.0/24 --csv result.csv
scan-phone-network --oui oui.csv          # 제조사 DB 확장
```

---

## 제조사 식별률 높이기 (선택)

IEEE 공식 OUI 목록을 내려받아 **exe 와 같은 폴더에 `oui.csv`** 로 두면 자동 로드됩니다.
다운로드: https://standards-oui.ieee.org/oui/oui.csv

---

## 권한 참고
- 핑/ARP/SSDP/포트 스캔: **일반 권한**으로 동작
- **DHCP 정밀 탐지**: UDP 68 포트를 Windows DHCP 클라이언트가 점유하면 건너뜀.
  필요 시 관리자 권한으로 실행하면 정확도가 올라갑니다.

## ⚠️ 사용 범위
**본인이 관리하거나 점검 권한이 있는 학교 업무망에서만** 사용하세요.

## 라이선스
[MIT License](LICENSE) © 2026 TeaveloperHQ
