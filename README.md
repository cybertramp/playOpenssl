## Openssl with C

이 프로젝트는 Digicap에 인턴으로 근무하면서 공부하고 작성했던 소스코드와 프로그램을 모아둔 레포지토리입니다. CAN 네트워크에서 수집한 트래픽을 전송하기 위한 프로그램 작성을 목표로 두고 프로그래밍하였습니다.

This project is a repository of source code and programs that I worked on while working as an intern at Digicap. I have programmed with the aim of creating a program to transmit the traffic collected from the CAN network.

### 작성 기간)

19.07.10 - 19.07.26

### 목록)

- helloworld

  설치 환경 테스트용 helloworld

- test_md5

  입력 파라미터에 대한 md5

- test_sha256

  입력 파라미터에 대한 sha256

- test_sha512

  입력 파라미터에 대한 sha512

- test_file_sha256

  파일에 대한 sha256

- test_HMAC_sha256

  keyfile과 datafile에 대한 HMAC-SHA256

- test_des_ori

  DES 대칭키 암호화

- test_des

  EVP를 사용한 DES 대칭키 암호화

- test_aes

  AES 암호화

- test_file_aes

  파일에 대한 AES 암호화

- test_file_rsa

  파일에 대한 RSA 암호화

- test_socket_echo_client

  에코 프로그램 - 클라이언트

- test_socket_echo_server

  에코 프로그램 - 서버

- canlogger

  CAN 로그를 암호화 전송하기 위한 프로그램

  키교환 - 비대칭키를 통한 세션키 암복호화 - 세션키를 통한 데이터 암복호화 전송

- chain-verify

  x509 pem 형식의 인증서를 생성하고 검증하는 프로그램

  - 체인 검증
  - CN 검증
  - 만료 기간 검증