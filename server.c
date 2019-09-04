#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/epoll.h> // I/O event notification facility *(for linux)
#include <errno.h>
#include <stddef.h>
#include <unistd.h>
#include<signal.h>
#include <fcntl.h>

#define MAXSIZE 1024
//epoll 最多累積的 EVENT 數
#define EPOLL_MAXEVENTS 64
//epoll_wait 的 timeout 時間
#define EPOLL_TIMEOUT 5000

typedef struct _SocketClient
{
    int clientFd;
    char actionType[32];
    int connected;
}SocketClient;

SocketClient Client[2] = {0};

// 將 SOCK 加入 EVENT
static void add_event(int epollfd,int fd,int state);
// 將 SOCK 刪除
static void delete_event(int epollfd,int fd,int state);
// 轉換 EVENT 的狀態
static void modify_event(int epollfd,int fd,int state);
// 允許 SOCK 連接
static void accpet_handler(int fd, int epollfd);
// 辨別使用者
static void discriminate_client(int clientFd, char *buf);
// 設定爲非阻塞狀態
static void set_non_block(int fd);
// 讀取EVENT中的資料
static void do_read(int epollfd, int eventfd);
// 寫入
static void do_write(int epollfd,int eventfd);

// UDS 檔案名稱
const char* filename = "socket";

static void add_event(int epollfd,int fd,int state)
{
    struct epoll_event ev;
    ev.events = state;
    ev.data.fd = fd;
    epoll_ctl(epollfd,EPOLL_CTL_ADD,fd,&ev);
}

static void delete_event(int epollfd,int fd,int state)
{
    struct epoll_event ev;
    ev.events = state;
    ev.data.fd = fd;
    epoll_ctl(epollfd,EPOLL_CTL_DEL,fd,&ev);
}

static void modify_event(int epollfd, int fd, int state)
{
    struct epoll_event ev;
    ev.events = state;
    ev.data.fd = fd;
    epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &ev);
}

static void discriminate_client(int clientFd, char *buf)
{
    if(strcasecmp(buf, "local") == 0)
    {
        Client[0].clientFd = clientFd;
        Client[0].connected = 1;
        strcpy(Client[0].actionType, buf);
    }
    if(strcasecmp(buf, "cloud") == 0)
    {
        Client[1].clientFd = clientFd;
        Client[1].connected = 1;
        strcpy(Client[1].actionType, buf);
    }
}

static void set_non_block(int fd)
{
    int flags;
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl(F_GETFL) failed");
        return ;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        perror("fcntl(F_SETFL) failed");
        return ;
    }
}

static void accpet_handler(int fd, int epollfd)
{
    int clientFd;
    char buf[32];
    // 接受 CLIENT
    clientFd = accept(fd, NULL, NULL);
    // 將 CLIENT 轉換成非阻塞
    set_non_block(clientFd);
    if (clientFd == -1)
    {
        // 判斷 I/O 不可讀, 非阻塞狀態下沒有連接將返回 EWOULDBLOCK
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
        {
            return ;
        } else 
        {
            perror("accpet error:");
        }
    }
    // 接收第一次訊息
    if (recv(clientFd, buf, sizeof(buf), 0) >= 0)
    {
        // 將 CLIENT 加入 EPOLL內
        add_event(epollfd, clientFd, EPOLLIN);
        // 判斷 CLIENT 身份
        discriminate_client(clientFd, buf);
    }

}

static void do_read(int epollfd, int eventfd)
{
	uint16_t data[64] = {0};
    char buf[1024] = {0};
    int flag = 0, ret = 0;
    while (1)
    {
        flag = (Client[0].clientFd == eventfd)? 1 : 0;
        ret = recv(eventfd, buf, sizeof(buf), 0);
        if (0 < ret)
        {
            send(Client[flag].clientFd, buf, sizeof(buf), 0);
            return ;
        }
        if (0 >= ret)
        {
            int origin = flag ^ 1;
            Client[origin].connected = 0;
            if (close(Client[origin].clientFd) == -1)
            {
                return ;
            }
            break;
        }
    }
}

static void do_write(int epollfd,int eventfd)
{
    uint16_t data[64]={0};
    char buf[1024]={0};
    int flag = 0;
    while (send(eventfd, buf, sizeof(buf), 0) >= 0)
    {
        for (size_t i = 0; i < 2; i++)
        {
            flag = i ^ 1;
            if (Client[i].clientFd == eventfd)
                break;
        }
        recv(Client[flag].clientFd, buf, sizeof(buf), 0);
        modify_event(epollfd, Client[flag].clientFd, EPOLLIN);
        return ;
    }
}

int main(int argc, char const *argv[])
{
    int server_fd, count, res, epollfd, eventfd, error;
    struct epoll_event events[EPOLL_MAXEVENTS];
    char buf[MAXSIZE];
	uint16_t data[64]={0};

	server_fd = socket(AF_UNIX, SOCK_STREAM, 0);

    struct sockaddr_un un;
	if(server_fd < 0)
	{
		printf("failed to create socket\n");
		return 1;
	}
    un.sun_family = AF_UNIX;
	unlink(filename);
	strcpy(un.sun_path, filename);
	if(bind(server_fd, (struct sockaddr*)&un, sizeof(un)) < 0)
	{
		printf("failed to bind\n");
		return 1;
	}

	if(listen(server_fd, 5) < 0)
	{
		printf("failed to listen\n");
		return 1;
	}
    memset(buf, 0, MAXSIZE);
    epollfd = epoll_create(sizeof(server_fd)/sizeof(int));
    add_event(epollfd, server_fd, EPOLLIN);
    while (1)
    {
        count = epoll_wait(epollfd, events, EPOLL_MAXEVENTS, EPOLL_TIMEOUT);
        // 超時或等待錯誤則跳出迴圈
        if(count == -1) {
            printf("epoll_wait failed.\n");
            return 1;
        }
        else if (count == 0) {
            fprintf(stderr, "no socket ready for read within %d secs\n", EPOLL_TIMEOUT / 1000);
            continue;
        }
        // 收到SOCK 進入
        for (size_t i = 0; i < count; i++)
        {
            eventfd = events[i].data.fd;
            // 收到 CLIENT 中斷, 或異常時關閉 EVENT
            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))
            {
                close (eventfd);
                continue;
            }
            if ((server_fd == eventfd) && (events[i].events & EPOLLIN))
                accpet_handler(server_fd, epollfd);
            else if ((events[i].events & EPOLLIN) && (Client[0].connected != 0) && (Client[1].connected != 0))
                do_read(epollfd, eventfd);
            else if (events[i].events & EPOLLOUT && (Client[0].connected != 0) && (Client[1].connected != 0))
                do_write(epollfd, eventfd);
        }
    }
    close(epollfd);
    close(server_fd);
    free(events);
    return 0;
}
