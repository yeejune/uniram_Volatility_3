# uniram_Volatility_3

윈도우 및 리눅스 시스템의 메모리 덤프 파일(`.raw`, `.img`, `.vmem`)을 자동으로 탐지하고, **Volatility 3 Framework**를 병렬 프로세싱으로 구동하여 실시간 위협 및 데이터 유출 흔적을 정밀하게 추출·압축하는 자동화 포렌식 도구입니다.

## Key Features
- **OS 프로파일 자동 감지**: Windows 및 Linux 메모리 이미지 자동 식별 및 적합한 플러그인 매핑
- **멀티스레딩 병렬 수집**: 고용량 메모리 이미지 분석 시 CPU 코어를 활용한 속도 최적화
- **정밀 화이트리스트 필터링 (오탐 제거)**: SSDT, 서비스, 레지스트리 등의 가비지 데이터를 걷어내고 실제 침해 징후 및 내부자 유출 흔적(100배 압축)만 탐지
- **AI-Ready 마크다운 생성**: 분석 결과를 구조화된 마크다운(`MD`) 및 `JSON` 보고서로 출력하여 LLM(AI) 분석 및 타겟 로그 수집(EVTX) 연계 최적화

## Output Structure
```text
forensic_output/
├── analysis_report.txt     # 콘솔 출력용 요약 보고서
├── analysis_report.json    # SIEM 및 데이터 연동용 JSON
├── Windows_10.md           # AI 컨텍스트 주입용 정제된 마크다운 보고서
└── [plugin_name].txt       # 원본 로우 데이터 아카이브 (cmdline, netscan 등)
```

## HOW to Usage

Prerequisites
본 도구는 Volatility 3 환경이 시스템 패스(PATH)에 등록되어 있거나 파이썬 모듈로 설치되어 있어야 합니다.

```text

Bash
# 의존성 패키지 자동 설치 및 분석 실행
python enhance_memory.py <메모리_이미지_경로> -o <출력_디렉토리>

# 예시
python enhance_memory.py .\Rocba-Memory.raw -o .\forensic_output
🛠️ Detection Logic & Analytics
프로세스 메모리 무결성: pslist와 psscan 교차 검증을 통한 은닉 프로세스(Hidden Process) 추적

지속성 메커니즘 분석: 비표준 외부 경로 서비스(svcscan) 및 자동 실행 명령 제어권 변조 식별

유출 채널 추적: 웹 브라우저(chrome) 및 사내 메신저(Slack)의 실행 인자값(cmdline) 분석을 통한 내부 데이터 유출 경로 구체화

```

---

이제 정제된 14건의 결과 데이터를 들고 위의 2번 파워쉘 스크립트를 감감 PC에서 구동하여 이벤트 로그를 가져오시면 됩니다. 수집된 텍스트 로그를 AI에 주면, 계정 연동 실수와 해킹의 주체를 칼로 자르듯 명확하게 판별해 줄 것입니다!

---



use Volatility in any os????

