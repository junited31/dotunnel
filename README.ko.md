# dotunnel

<p align="center"><img src="assets/dotunnel.png" alt="dotunnel: 속이 뚫린 원기둥으로 형상화한 터널" width="840"></p>

[English](README.md) | **한국어**

`dotunnel`은 Linux 서버에서 실행하는 자체 호스팅 stdio MCP 서버이자
private Secure MCP Tunnel 연결 도우미입니다. 지정한 workspace의 파일 도구와
관리자가 정의한 고정 작업만 제공합니다. 호스팅 서비스나 공개 MCP endpoint가
아닙니다.

| 구분 | 포함 내용 |
|---|---|
| 기본 | Tunnel 설정·진단 도우미, 제한된 workspace 파일 도구와 고정 작업 |
| 선택 | 별도 설치한 Codex·Claude Code·OMP CLI용 격리 작업 |

## 요구사항

- root가 아닌 Linux 계정, Python 3.11 이상과 `python3`, `venv`, `pip`.
- 한 줄 설치에는 `curl`, `sha256sum`이 필요하며 `uv`는 필요하지 않습니다.
- ChatGPT/Platform 자격과 권한, OpenAI Tunnel ID와 제한된 runtime key,
  공식 `tunnel-client`는 별도 준비해야 합니다. `dotunnel`은 권한을 부여하거나
  이를 대신 제공하지 않습니다.

## 설치

GitHub 로그인 없이 현재 릴리스를 설치합니다.

```sh
curl -fsSL https://raw.githubusercontent.com/junited31/dotunnel/main/install.sh | sh
```

설치 스크립트는 고정된 wheel을 검증한 뒤
`$HOME/.local/share/dotunnel/venv`에 설치하고
`$HOME/.local/bin/dotunnel`을 제공합니다. piped stdin에서 setup을 실행하지
않으며, 공식 client 설치나 계정·권한·key·Tunnel 설정·shell startup·서비스
변경도 하지 않습니다. 기존 설치 경로나 무관한 launcher를 덮어쓰지 않습니다.
기존 설치에는 `dotunnel update`를 사용하세요. `dotunnel`을 찾지 못하면
`$HOME/.local/bin`을 직접 `PATH`에 추가하거나 절대 경로로 실행하세요.

wheel을 직접 내려받으려면 [수동 설치 안내](docs/guide.ko.md#수동-설치)를 참고하세요.

## 설정

setup은 대화형 터미널에서 실행해야 합니다. 공식 client를 별도로 설치하고
checksum을 검증하세요. 계정 권한, Tunnel ID, Restricted runtime key도 직접
준비해야 합니다. `dotunnel`은 이를 대신 만들 수 없습니다.

```sh
"$HOME/.local/share/dotunnel/venv/bin/dotunnel" setup --directory "$HOME/.dotunnel-setup"
```

setup은 private profile/config와 입력한 key를 별도 workspace 밖에 저장합니다.
workspace는 `tasks: []`로 시작합니다. 계정 격리, private 설치와 ChatGPT 연결은
[상세 안내](docs/guide.ko.md)를 참고하세요.

## 명령

| 명령 | 용도 |
|---|---|
| `dotunnel help` | 사용법 표시 |
| `dotunnel setup` | Tunnel 설정 생성 또는 선택 CLI 연동 설정 |
| `dotunnel doctor` | 설정·client·연결 상태 읽기 전용 진단 |
| `dotunnel update` | 최신 안정 release 확인 후 대화형 업데이트 |

## 안전

- root가 아닌 계정으로 실행하세요. 광범위한 그룹·sudo가 없는 전용 계정을
  권장합니다. 프로젝트는 계정을 만들거나 권한을 변경하지 않습니다.
- 설치 프로그램, trusted 설정/credential, writable workspace를 분리하세요.
  초기 `tasks: []`이며 credential은 workspace 밖에 저장됩니다.
- 고정 작업은 MCP 실행 계정의 전체 OS 권한으로 실행됩니다. 고정 명령이나
  workspace는 sandbox가 아니므로 코드와 side effect를 검토하세요.
- stdio MCP에는 별도 사용자 인증이 없습니다. 접근 주체를 제한하고 허용 파일과
  작업 결과에 민감 정보가 없는지 확인하세요.
- 선택 CLI 작업에는 Bubblewrap이 필요합니다. native CLI는 같은 사용자로 실행되어
  참조 credential을 읽을 수 있고 허용 내용은 provider로 전송될 수 있습니다.
  candidate는 자동 적용·검증되지 않습니다.
- `curl | sh`는 저장소의 설치 스크립트를 현재 사용자 권한으로 실행합니다.
  스크립트를 신뢰·검토하세요. wheel checksum이 shell 스크립트까지 무조건
  신뢰해도 된다는 뜻은 아닙니다.
- source 개발 시 [커밋 전 secret 검사](docs/guide.ko.md#7-secret을-공개하지-않는-개발)를 켜고 runtime/key 파일을 checkout 밖에 두세요.

[상세 안내](docs/guide.ko.md) · [설계](DESIGN.md) ·
[config 예시](config.example.json) · [라이선스](LICENSE)
