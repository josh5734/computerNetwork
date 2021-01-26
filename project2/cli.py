import socket
import threading
import signal
import sys

lock = threading.Lock()


userNum = 0


def receivemsg(client_socket):
    while True:
        try:
            recvMessage = client_socket.recv(1024).decode()
            if not recvMessage:
                break
            print(recvMessage)

        except KeyboardInterrupt:
            pass


# 서버의 주소입니다. hostname 또는 ip address를 사용할 수 있습니다.
host = sys.argv[1]
# 서버에서 지정해 놓은 포트 번호입니다.
port = int(sys.argv[2])
# 소켓 객체를 생성합니다.
# 주소 체계(address family)로 IPv4, 소켓 타입으로 TCP 사용합니다.
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 지정한 HOST와 PORT를 사용하여 서버에 접속합니다.
client_socket.connect((host, port))

# 쓰레딩을 시작합니다.
t = threading.Thread(target=receivemsg, args=(client_socket,))
t.daemon = True
t.start()


# ctrl+c 입력을 처리하는 함수
# ctrl+c가 입력되면 종료합니다.
def signal_handler(sign, frame):
    print("\nexit")
    client_socket.close()
    sys.exit()


# 메시지를 전송합니다.
while True:
    stop = False
    signal.signal(signal.SIGINT, signal_handler)
    message = input()
    client_socket.sendall(message.encode('utf-8', "ignore"))
    print("[You]", message)
