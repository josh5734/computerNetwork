import threading
import socket
import sys
import time

buffer_size = 4096
lock = threading.Lock()

# 유저가 입력하는 서버 포트 번호
proxy_port = int(sys.argv[1])


# filtering, redirection을 위한 전역변수
filtered_url = "yonsei"
redirected_url = "http://linuxhowtos.org/"
redirected_server = "linuxhowtos.org"
redirected_host = "linuxhowtos.org"

# filtering, redirection에 대한 flag 변수
image_filtering = {"flag": False}
redirection_flag = {"flag": False}
print_number = 0


# header에서 request, user_agent 부분을 parsing하는 함수
def request_parser(header_lines):
    request = ""
    user_agent = ""

    for i in range(len(header_lines)):
        if b'HTTP' in header_lines[i]:
            request = header_lines[i]
        elif b'User-Agent' in header_lines[i]:
            user_agent = header_lines[i]
    data = {
        "request": request.decode(encoding="utf-8", errors="ignore"),
        "user_agent": user_agent.decode(encoding="utf-8", errors="ignore")[12:],
    }
    return data


# header에서 server_url과 full_url에 대한 정보를 parsing하는 함수 / domain을 얻기 위함
def domain_parser(header_lines):
    first_line_tokens = header_lines[0].split()
    url = first_line_tokens[1].decode(encoding="utf-8", errors="ignore")
    http_pos = url.find("://")
    server_url = url[(http_pos+3):]
    full_url = url[(http_pos+3):]
    webserver_pos = server_url.find("/")
    server_url = server_url[:webserver_pos]

    data = {
        "server_url": server_url,
        "full_url": full_url,
    }
    return data


# http header에서 status, content_type, content_length 정보 parsing하고 return해주느 함수
def http_response_parser(replies):
    status = ""
    content_type = "Not Specified"
    content_length = "0"
    for i in range(len(replies)):
        if b'HTTP' in replies[i]:
            status = replies[i]
        if b'Content-Type' in replies[i]:
            content_type = replies[i].decode(
                encoding="utf-8", errors="ignore").split()[1]
        if b'Content-Length' in replies[i]:
            content_length = replies[i].decode(
                encoding="utf-8", errors="ignore").split()[1]

    data = {
        "status": status.decode(encoding="utf-8", errors="ignore"),
        "content_type": content_type,
        "content_length": content_length,
    }

    return data


# image filtering을 위한 함수
def image_filter(client_data):
    global image_filtering
    data = client_data
    lines = data.splitlines()
    full_url = domain_parser(lines)["full_url"]

    # ?image_off라는 query가 있을 때
    if("?image_off" in full_url):
        image_filtering.update(flag=True)

    # ?image_on라는 query가 있을 때
    elif("?image_on" in full_url):
        image_filtering.update(flag=False)

    return data

# URL redirection을 위한 함수 // client의 request에서 request, host 부분을 parsing / change


def redirection(c_data):
    global filtered_url, redirected_url, redirected_host
    client_data = c_data
    lines = client_data.splitlines()

    lock.acquire()

    redirection_flag.update(flag=True)
    server_url = redirected_url
    first_line_tokens = lines[0].split()
    first_line_tokens[1] = server_url.encode()
    lines[0] = b' '.join(first_line_tokens)

    second_line_tokens = lines[1].split()
    second_line_tokens[1] = redirected_host.encode()
    lines[1] = b' '.join(second_line_tokens)

    change = client_data.split(b'\r\n')
    change[0] = lines[0]
    change[1] = lines[1]
    client_data = b'\r\n'.join(change)
    lines = client_data.splitlines()
    request = request_parser(lines)["request"]
    user_agent = request_parser(lines)["user_agent"]

    lock.release()

    data = {
        "client_data": client_data,
        "request": request,
        "user_agent": user_agent,
    }

    return data

# thread function : client_socket, addr, data를 parameter로 함
# client_data에서 server에 대한 정보 등을 parsing하고, proxy socket에게 넘겨주는 역할을 함


def p_thread(client_socket, client_addr, client_data):
    global image_filtering, filtered_url, redirected_url, redirected_server, redirection_flag
    storage = []

    storage.append("[CLI connected to {}:{}]".format(
        client_addr[0], client_addr[1]))
    # Client Browser Requests appears here
    try:
        # lines: client_data를 line 단위로 split 후 parsing하기 위함
        lines = client_data.splitlines()
        request = request_parser(lines)["request"]
        user_agent = request_parser(lines)["user_agent"]

        storage.append("[CLI ==> PRX --- SRV]")
        storage.append(f"> {request}")
        storage.append(f"> {user_agent}")

        ###############################################################
        server_url = domain_parser(lines)["server_url"]
        server_port = 80
        ################## Redirection ##############################
        # 만약 filtered_url이 현재 server_url에 포함되어 있다면 Redirection 진행
        if server_url.find(filtered_url) != -1:
            client_data = redirection(client_data)["client_data"]
            request = redirection(client_data)["request"]
            user_agent = redirection(client_data)["user_agent"]

            proxy_server(redirected_server, server_port, client_socket,
                         client_addr, client_data, request, user_agent, storage)
        else:
            lock.acquire()
            redirection_flag.update(flag=False)
            lock.release()

            proxy_server(server_url, server_port, client_socket,
                         client_addr, client_data, request, user_agent, storage)
    except Exception as e:
        pass

# 메인 proxy_server에 대한 함수
# server와 client의 정보를 가지고 socket을 생성한다.
# client의 요청을 server에게 send하고, server의 응답을 recv하여 client에게 send해준다.


def proxy_server(server_url, server_port, client_socket, client_addr, client_data, request, user_agent, storage):
    global print_number, image_filtering, redirection_flag
    try:
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # print("연결?")
        proxy_socket.connect((server_url, server_port))
        storage.append(f"[SRV connected to {server_url}:{server_port}]")

        proxy_socket.send(client_data)

        storage.append("[CLI --- PRX ==> SRV]")
        storage.append(f"> {request}")
        storage.append(f"> {user_agent}")

        proxy_socket.setblocking(0)
        total_data = []
        data = ""
        timeout = 2
        begin = time.time()

###################################################################################
        # http 요청은 TCP를 이용하기 때문에 timeout을 이용하여 손실되는 데이터가 없도록 한다.
        while True:
            # print("while...")
            # if you got some data, then break after timeout
            if total_data and time.time()-begin > timeout:
                # print("?????????/")
                break
            # if you got no data at all, wait a little longer, twice the timeout
            elif time.time()-begin > timeout * 2:
                # print("fffffffffffffff")
                break

            # Read reply or data to from end web server
            try:
                reply = proxy_socket.recv(8192)
                # print(reply)
                if reply:
                    total_data.append(reply)
                    begin = time.time()
                else:
                    time.sleep(0.1)
            except Exception as e:
                pass

        # join all parts to make final string
        data = b''.join(total_data)
################################################################################
        datas = data.splitlines()
        status = http_response_parser(datas)["status"]
        ctype = http_response_parser(datas)["content_type"]
        clength = http_response_parser(datas)["content_length"]
        storage.append("[CLI --- PRX <== SRV]")
        storage.append(f'> {status}')
        storage.append(f'> {ctype} {clength}bytes')

        # image filtering 기능이 작동되면
        # Content-type = image인 response의 body를 drop하여 client에게 전송한다.
        if image_filtering.get('flag') == True and 'image' in ctype:
            clength = "0"
            data = data.split(b'\r\n\r\n')[0]
            # storage.append(data)

        client_socket.send(data)  # send reply back  to client

        # send notification to proxy server
        storage.append("[CLI <== PRX --- SRV]")
        storage.append(f'> {status}')
        storage.append(f'> {ctype} {clength}bytes')

        proxy_socket.close()
        client_socket.close()
        storage.append("[CLI disconnected]")
        storage.append("[SRV disconnected]")
############################ 생성된 로그 출력 ####################################
        lock.acquire()
        thread_num_pos = str(threading.currentThread()).find('-')
        thread_num = str(threading.currentThread())[thread_num_pos+1]
        print_number += 1
        storage.insert(
            0, f"{print_number} [Conn:    {thread_num}/    {threading.activeCount()}]")

        # image filtering, URL Redirection에 대한 flag를 확인하여 Indicator를 설정함
        if image_filtering.get('flag') == True:
            image_indicator = "O"
        elif image_filtering.get('flag') == False:
            image_indicator = "X"
        if redirection_flag.get('flag') == True:
            url_indicator = "O"
        elif redirection_flag.get('flag') == False:
            url_indicator = "X"
        storage.insert(
            1, f"[ {url_indicator} ] URL filter  |  [ {image_indicator} ] Image filter")
        storage.append("-----------------------------------------")
        storage.insert(2, " ")
        # 로그 출력
        for log in storage:
            print(log)
        lock.release()
########################################################################
    except Exception as e:
        proxy_socket.close()
        client_socket.close()
        sys.exit()


if __name__ == "__main__":
    # 소켓 객체 생성
    # 주소 체계(address family)로 IPv4, 소켓 타입: TCP
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Starting proxy server on port {}".format(proxy_port))
    print("-----------------------------------------")
    # WinError 10048 해결하기 위한 코드
    # Address already in use Error solution
    # future socket available
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # bind 함수는 소켓을 특정 네트워크 인터페이스와 포트 번호에 연결하는데 사용
    # HOST는 hostname, ip address, 빈 문자열 ""이 될 수 있음
    # 빈 문자열이면 모든 네트워크 인터페이스로부터의 접속을 허용
    # port는 1-65536 사이의 숫자를 사용 가능
    proxy_socket.bind(('0.0.0.0', proxy_port))
    # accept 함수에서 대기하다가 클라이언트가 접속하면
    # 클라이언트의 소켓과 클라이언트의 주소를 반환해서 저장
    proxy_socket.listen()

    # Main server loop
    while True:
        try:
            client_socket, client_addr = proxy_socket.accept()
            # When a connection arrives from the client, accept it, receive the clients data ( Browser request )
            client_data = client_socket.recv(buffer_size)

            # client data가 존재하고
            if client_data:
                # client_data에서 parsing하여 Request Method가 "GET"일 때만 사용
                method = client_data.splitlines()[0].decode(
                    encoding="utf-8", errors="ignore").split(' ')[0]
                if method == "GET":
                    client_data = image_filter(client_data)

                    t = threading.Thread(target=p_thread, args=(
                        client_socket, client_addr, client_data))

                    t.daemon = True
                    t.start()
            else:
                pass

        # Ctrl+C -> Terminate
        except KeyboardInterrupt:
            proxy_socket.close()
            sys.exit(1)
    proxy_socket.close()
