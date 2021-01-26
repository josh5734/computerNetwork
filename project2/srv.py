import socket
import threading
import signal
import sys


userNumber = 0
users = {}
lock = threading.Lock()

# 유저가 들어오면 User 목록에 추가합니다.


def adduser(userid, clients):
    # lock.acquire()
    users[userid] = clients
    # lock.release()

# 유저가 나가면 userNumber를 줄이고 User목록에서 제거합니다.


def removeuser(userid):
    global userNumber
    userNumber -= 1
    # lock.acquire()
    del users[userid]
    # lock.release()


# 유적 나가면 removeuser()함수를 호출한 뒤, 알림을 띄웁니다.
def userleaves(client_socket, addr):
    global userNumber
    removeuser(id(client_socket))
    if userNumber <= 1:
        print("< The user {}:{} left ({} user online)".format(
            addr[0], addr[1], userNumber))
        for clients in users.values():
            leave_ip = addr[0]
            leave_port = addr[1]
            if clients != client_socket:
                clients.sendall(("< The user " + str(leave_ip) + ":"+str(leave_port) +
                                 " left ("+str(userNumber)+" " + "user online)").encode())

    else:
        print("< The user {}:{} left ({} users online)".format(
            addr[0], addr[1], userNumber))
        for clients in users.values():
            leave_ip = addr[0]
            leave_port = addr[1]
            if clients != client_socket:
                clients.sendall(("< The user " + str(leave_ip) + ":"+str(leave_port) +
                                 " left ("+str(userNumber)+" " + "users online)").encode())


# 유저가 로그인하면 알림을 띄웁니다.
def login_notice(client_socket, addr):
    if userNumber == 1:
        print('> New user {}:{} entered ({} user online)'.format(
            addr[0], addr[1], userNumber))
        client_socket.sendall(
            ("> Connected to the chat server " + "("+str(userNumber)+" user online)").encode())
        for clients in users.values():
            sender_ip = addr[0]
            sender_port = addr[1]
            if clients != client_socket:
                clients.sendall(
                    ("> New user "+str(sender_ip)+":"+str(sender_port)+" entered (" + str(userNumber)+" user online)").encode())

    else:
        print('> New user {}:{} entered ({} users online)'.format(
            addr[0], addr[1], userNumber))
        client_socket.sendall(
            ("> Connected to the chat server " + "("+str(userNumber)+" users online)").encode())
        for clients in users.values():
            sender_ip = addr[0]
            sender_port = addr[1]
            if clients != client_socket:
                clients.sendall(
                    ("> New user "+str(sender_ip)+":"+str(sender_port)+" entered (" + str(userNumber)+" users online)").encode())


# 각 Thread에 대하여 메시지를 수신하고 출력한 뒤, 다른 클라이언트에게도 에코합니다.
def threading_func(client_socket, addr):
    login_notice(client_socket, addr)
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if not message:
                break
            print('[{}:{}] {}'.format(addr[0], addr[1], message))

            for clients in users.values():
                sender_ip = addr[0]
                sender_port = addr[1]
                if clients != client_socket:
                    # clients.send(message.encode())
                    clients.sendall(
                        ("["+str(sender_ip)+":"+str(sender_port)+"] "+message).encode())
        except ConnectionResetError:
            break

    userleaves(client_socket, addr)
    client_socket.close()


# 매개변수로 host, port 정보를 입력받습니다.
host = sys.argv[1]
port = int(sys.argv[2])
print("Chat Server started on port " + str(port)+".")

# 소켓 객체 생성
# 주소 체계(address family)로 IPv4, 소켓 타입: TCP
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# WinError 10048 해결하기 위한 코드
# Address already in use Error solution
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


# bind 함수는 소켓을 특정 네트워크 인터페이스와 포트 번호에 연결하는데 사용
# HOST는 hostname, ip address, 빈 문자열 ""이 될 수 있음
# 빈 문자열이면 모든 네트워크 인터페이스로부터의 접속을 허용
# port는 1-65536 사이의 숫자를 사용 가능
server_socket.bind((host, port))

# accept 함수에서 대기하다가 클라이언트가 접속하면
# 클라이언트의 소켓과 클라이언트의 주소를 반환해서 저장
server_socket.listen()


# ctrl+c 입력을 처리하는 함수
# ctrl+c 가 입력되면 stop 변수를 True로 변환해줍니다.
def signal_handler(sign, frame):
    print("\nexit")
    server_socket.close()
    sys.exit()


# 메시지를 전송합니다
# 무한루프를 돌면서
while True:
    interrupted = False
    signal.signal(signal.SIGINT, signal_handler)

    # 서버가 클라이언트의 접속을 허용하도록 함
    client_socket, addr = server_socket.accept()

    userNumber += 1
    userid = id(client_socket)
    adduser(userid, client_socket)

    t = threading.Thread(target=threading_func, args=(client_socket, addr))
    t.daemon = True
    t.start()

    #_thread.start_new_thread(threading_func, (client_socket, addr))
