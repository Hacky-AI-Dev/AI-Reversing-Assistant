# AI Reversing Assistant

An AI-powered plugin for IDA Pro that automates variable and function analysis through intelligent name suggestions.

## Features

- **Variable Analysis**: Automatically analyzes variables at cursor position and suggests meaningful names
- **Function Analysis**: Analyzes entire functions and provides improved signatures and comments
- **Hex-Rays Integration**: Works seamlessly with IDA Pro's Hex-Rays decompiler
- **Smart Detection**: Automatically detects whether to analyze variables or functions based on cursor position
- **Configurable Language**: Supports both English and Korean for comments and analysis results

## Requirements

- IDA Pro 8.x or later
- Hex-Rays Decompiler (for full functionality)
- Python 3.11 (tested)
- Valid API key from [hacky-ai.com](https://hacky-ai.com)

## Installation

1. Download the `ai_reversing_assistant.py` file
2. Place it in your IDA Pro plugins directory
3. Configure your API key (see Setup section below)
4. Restart IDA Pro

## Setup

### API Key Configuration

1. Obtain an API key from [hacky-ai.com](https://hacky-ai.com)
2. Open the `ai_reversing_assistant.py` file
3. Replace `<Enter your API Key Here>` with your actual API key

```python
# In ai_reversing_assistant.py, line ~105
self.api_key = "your_actual_api_key_here"
```

### Language Settings

The plugin supports both English and Korean for analysis results and comments. You can change the language through the settings dialog (see Usage section).

## Usage

### Hotkeys

- **Shift+E**: Perform AI analysis (automatically detects variable or function)

### Manual Analysis

1. **Variable Analysis**:
   - Place cursor on a variable in the Hex-Rays pseudocode view
   - Press `Shift+E` or run the analysis command
   - The plugin will suggest a better variable name

2. **Function Analysis**:
   - Place cursor inside a function
   - Highlight the function name
   - Press `Shift+E` or run the analysis command
   - The plugin will suggest improved function signature and comments

### Settings

- Access settings through the plugin menu
- Configure comment language (English/Korean)
- Settings are stored in memory only (no persistent file storage)



---

# AI 리버싱 어시스턴트

IDA Pro에서 AI를 활용하여 변수와 함수를 자동으로 분석하고 의미 있는 이름을 제안하는 플러그인입니다.

## 기능

- **변수 분석**: 커서 위치의 변수를 자동으로 분석하여 의미 있는 이름을 제안
- **함수 분석**: 전체 함수를 분석하여 개선된 시그니처와 주석을 제공
- **Hex-Rays 통합**: IDA Pro의 Hex-Rays 디컴파일러와 완벽하게 통합
- **스마트 감지**: 커서 위치에 따라 변수 또는 함수 분석을 자동으로 결정
- **언어 설정**: 분석 결과와 주석에 영어와 한국어 지원

## 요구사항

- IDA Pro 8.x 이상
- Hex-Rays Decompiler (전체 기능 사용을 위해)
- Python 3.11 (테스트됨)
- [hacky-ai.com](https://hacky-ai.com)에서 발급받은 유효한 API 키

## 설치

1. `ai_reversing_assistant.py` 파일을 다운로드
2. IDA Pro 플러그인 디렉토리에 파일을 복사
3. API 키 설정 (아래 설정 섹션 참조)
4. IDA Pro 재시작

## 설정

### API 키 설정

1. [hacky-ai.com](https://hacky-ai.com)에서 API 키를 발급받으세요
2. `ai_reversing_assistant.py` 파일을 열어주세요
3. `<Enter your API Key Here>`를 실제 API 키로 교체하세요

```python
# ai_reversing_assistant.py 파일의 ~105번째 줄
self.api_key = "여기에_실제_API_키_입력"
```

### 언어 설정

플러그인은 분석 결과와 주석에 영어와 한국어를 지원합니다. 설정 다이얼로그를 통해 언어를 변경할 수 있습니다 (사용법 섹션 참조).

## 사용법

### 단축키

- **Shift+E**: AI 분석 실행 (변수 또는 함수 자동 감지)

### 수동 분석

1. **변수 분석**:
   - Hex-Rays 의사코드 뷰에서 변수에 커서를 놓으세요
   - `Shift+E`를 누르거나 분석 명령을 실행하세요
   - 플러그인이 더 나은 변수 이름을 제안합니다

2. **함수 분석**:
   - 함수 내부에 커서를 놓으세요
   - 함수 이름을 선택하세요
   - `Shift+E`를 누르거나 분석 명령을 실행하세요
   - 플러그인이 개선된 함수 시그니처와 주석을 제안합니다

### 설정

- 플러그인 메뉴를 통해 설정에 접근하세요
- 주석 언어 설정 (영어/한국어)
- 설정은 메모리에만 저장됩니다 (파일로 영구 저장되지 않음)



