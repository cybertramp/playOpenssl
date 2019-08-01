# canlogger

로그 데이터를 암호화 통신을 통해 수집하는 서버-클라이언트 프로그램

## 사용법

### Server

서버 실행

``` bash
$ ./main_canlogger_server [SERVER PORT]
```

### Client

클라이언트 실행

``` bash
$ ./main_canlogger_client [IP] [SERVER PORT] [Logfile name]
```

- IP: 접속할 서버의 주소
- SERVER PORT: 접속할 서버의 포트
- Logfile name: 서버에 전송할 로그 파일

## 동작 과정

1. 서버
   - 로컬 pem 키생성 확인 및 키 생성
   - 키 교환
     - 클라이언트측 공개키 존재 여부 확인
     - 공개키 전달
     - 공개키에 대한 MAC 전달
   - 세션 키 전달
     - 세션 키 생성
     - 세션 키 암호화 및 전송
     - 세션 키 확인
   - 로그파일 수집
     - 클라이언트로부터 암호화된 로그파일 수신
     - 세션키를 통한 로그파일 복호화
     - 로그파일 MAC 검증
   - 다음 수신 대기
2. 클라이언트
   - 키교환
     - 서버로 부터 공개키 수신
     - 서버로 부터 공개키 MAC 수신
     - 공개키 MAC  검증
   - 세션키 수신
     - 서버로 부터 암호화 된 세션키 수신
     - 세션 키 복호화
   - 로그파일 전송
     - 세션키를 통한 로그파일 암호화
     - 암호화된 로그파일 전송
     - 로그파일 MAC 전달
   - 종료

## 개발환경

- Virtualbox 6.0
  - 2CPU, 4GB, 40GB

- Ubuntu 16.04 LTS 64bit

- Eclipse CDT, gcc 5.5.0

- Openssl 1.0.1

## 디렉토리 내 파일 구성

### Server

- Sources

  - main.h

    헤더와 함수의 원형 선언이 있는 파일

  - main.c

    주 동작 부분의 소스 파일

  - subfunc.c

    부가 함수 부분의 소스 파일

- Debug

  - pri.key

    서버에 의해 생성되는 개인키

  - pub.key

    pri.key로 부터 생성되는 공개키, 해당 키는 키교환을 위해 클라이언트에게 전달됨

  - xxxxxx-xxxxxxout.log

    수신된 로그파일(년월일-시분초 형식으로 생성)

### Client

- Sources
  - main.h

    헤더와 함수의 원형 선언이 있는 파일

  - main.c

    주 동작 부분의 소스 파일

  - subfunc.c

    부가 함수 부분의 소스 파일

- Debug

  - pub.key

    서버에 의해 생성되는 공개키

  - can.log

    테스트용 can 로그 파일

  - can1mb.txt

    테스트용 1MB 크기 파일