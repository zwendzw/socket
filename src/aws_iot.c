#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stddef.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/epoll.h>

#include "modbus.h"
#include "cJSON.h"
#include "aws_iot_config.h"
#include "aws_iot_log.h"
#include "aws_iot_version.h"
#include "aws_iot_mqtt_client_interface.h"
#include "aws_iot_shadow_interface.h"

#define ACTIONTYPE "cloud"
#define EPOLL_TIMEOUT 5000
#define HOST_ADDRESS_SIZE 255
#define MAX_LENGTH_OF_UPDATE_JSON_BUFFER 400
#define EPOLLEVENTS 100
#define MAXSIZE 1024

// receive data from socket server
static void do_read(int epollfd, int eventfd);
// send data to socket server
void *send_data(const char * data);
// connect socket server
void *connect_socket();
// convert data to json format for AWS IOT delta
static bool build_json_for_reported(char *pJsonDocument, size_t maxSizeOfJsonDocument, const char *pReceivedDeltaData, uint32_t lengthDelta);
// connect AWS IOT
static IoT_Error_t connect_aws();
// AWS IOT (REPORT/ DELTA) handler
void *aws_iot_register();
// convert data to json format for AWS IOT reported
char *create_reported_helper(char **data);
// update shadow callback
static void update_status_callback(const char *pThingName, ShadowActions_t action, Shadow_Ack_Status_t status, const char *pReceivedJsonDocument, void *pContextData);
// reported to AWS IOT
void iot_reported(AWS_IoT_Client *mqttClient, char *jsondocumentbuffer);
// delta callback
static void delta_callback(const char *pJsonValueBuffer, uint32_t valueLength, jsonStruct_t *pJsonStruct_t);
// add epoll event
static void add_event(int epollfd,int fd,int state);
// change epoll event state
static void modify_event(int epollfd,int fd,int state);
// socket client handler
static void accpet_handler(int fd, int epollfd);
// socket server
void *sock_server();

// unix domain socket file address
const char* SERVER_ADDRESS = "iot-server";
const char* LOCAL_SERVER_ADDRESS = "ipc-server";

// AWS 相關變數
jsonStruct_t deltaObject;
AWS_IoT_Client mqttClient;

static char certDirectory[PATH_MAX + 1] = "jffs2/straw/certs";
static char HostAddress[HOST_ADDRESS_SIZE] = AWS_IOT_MQTT_HOST;
static uint32_t port = AWS_IOT_MQTT_PORT;
static bool messageArrivedOnDelta = false;
static char stringToEchoDelta[SHADOW_MAX_SIZE_OF_RX_BUFFER];

int sock_fd, ret;

int main(int argc, char const *argv[])
{
    IoT_Error_t rc = FAILURE;
    pthread_t recvthread, cloudthread;
    rc = connect_aws();
    if (SUCCESS != rc)
    {
        // TODO "錯誤控制(FAILURE, NETWORK_ERR_NET_UNKNOWN_HOST, TCP_CONNECTION_ERROR, SSL_CONNECTION_ERROR, NETWORK_SSL_CONNECT_TIMEOUT_ERROR, NETWORK_SSL_CERT_ERROR, NETWORK_SSL_WRITE_TIMEOUT_ERROR, MQTT_CONNECTION_ERROR, MQTT_CLIENT_NOT_IDLE_ERROR)"
    }
    pthread_create(&cloudthread, NULL, aws_iot_register, NULL);
    pthread_join(cloudthread, NULL);
}

static void add_event(int epollfd,int fd,int state)
{
    struct epoll_event ev;
    ev.events = state;
    ev.data.fd = fd;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
}

static void delete_event(int epollfd,int fd,int state)
{
    struct epoll_event ev;
    ev.events = state;
    ev.data.fd = fd;
    epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &ev);
}

static void modify_event(int epollfd, int fd, int state)
{
    struct epoll_event ev;
    ev.events = state;
    ev.data.fd = fd;
    epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &ev);
}

static void set_non_block(int fd)
{
    int flags;
    flags = fcntl(fd, F_GETFL, 0);
    if (0 > flags) {
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
    clientFd = accept(fd, NULL, NULL);
    set_non_block(clientFd);
    if (clientFd == -1)
    {
        // 判斷 I/O 不可讀, 非阻塞狀態下沒有連接將返回 EWOULDBLOCK
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
        {
            // LOG ERROR
            exit(EXIT_FAILURE);
        }
    }
    add_event(epollfd, clientFd, EPOLLIN);
}

void *connect_socket()
{
    struct sockaddr_un un;
	char* buf;
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, LOCAL_SERVER_ADDRESS);
	sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(0 > sock_fd)
	{
        // LOG ERROR
		printf("failed to create socket in write_data\n");
	}
	if(connect(sock_fd, (struct sockaddr*)&un, sizeof(un)) < 0)
	{
        // LOG ERROR
		printf("failed to connect in write_data\n");
	}
    send(sock_fd, NULL, 1024, 0);
}

static void do_read(int epollfd, int eventfd)
{
    char *data[256];
    int flag = 0, ret = 0;
    memset(data, 0, sizeof(data));
    ret = recv(eventfd, &data, sizeof(data), 0);
    if ( 0 < ret)
    {
        aws_iot_shadow_yield(&mqttClient, 200);
        iot_reported(&mqttClient, create_reported_helper(data));
        IOT_DEBUG("\nREAD DATA: %s\n", &data);
    }
}

void *sock_server()
{
    int fd, ret, res, epollfd, eventfd;
    struct epoll_event events[EPOLLEVENTS];
	uint16_t data[64]={0};

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un un;
	if(fd < 0)
	{
		printf("failed to create socket\n");
		exit(1);
	}
    un.sun_family = AF_UNIX;
	unlink(SERVER_ADDRESS);
	strcpy(un.sun_path, SERVER_ADDRESS);
	if(bind(fd, (struct sockaddr*)&un, sizeof(un)) < 0)
	{
		printf("failed to bind\n");
		exit(1);
	}
	if(listen(fd, 5) < 0)
	{
		printf("failed to listen\n");
		exit(1);
	}
    epollfd = epoll_create(sizeof(fd)/sizeof(int));
    add_event(epollfd, fd, EPOLLIN);
    // 當觸發 DELTA 時, 狀態需先接受 DELTA , 否則會佔用 REPORT
    while (!messageArrivedOnDelta)
    {
        ret = epoll_wait(epollfd, events, EPOLLEVENTS, -1);
        printf("epoll_wait for %d.\n", ret);
        if(-1 == ret) {
            printf("epoll_wait failed.\n");
            exit(1);
        }
        else if (0 == ret) {
            continue;
        }
        for (size_t i = 0; i < ret; i++)
        {
            eventfd = events[i].data.fd;
            // 收到 CLIENT 中斷, 或異常時關閉 EVENT
            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))
            {
                fprintf(stderr, "close\n");
                close (eventfd);
                continue;
            }
            else if ((fd == eventfd) && (events[i].events & EPOLLIN))
                accpet_handler(fd, epollfd);
            else
            {
                do_read(epollfd, eventfd);
            }
            
        }
    }
}

void *send_data(const char * data)
{
    int ret;
    IOT_DEBUG("%s", data);
    u_int16_t send_data[64] = {0};
    connect_socket();
    ret = send(sock_fd, data, sizeof(send_data)/sizeof(send_data[0]), 0);
    close(sock_fd);
}

static void delta_callback(const char *pJsonValueBuffer, uint32_t valueLength, jsonStruct_t *pJsonStruct_t)
{
	IOT_UNUSED(pJsonStruct_t);

	IOT_DEBUG("Received Delta message %.*s", valueLength, pJsonValueBuffer);
	if (build_json_for_reported(stringToEchoDelta, SHADOW_MAX_SIZE_OF_RX_BUFFER, pJsonValueBuffer, valueLength))
    {
		messageArrivedOnDelta = true;
	}
}

static const cJSON *clean_delta(const char *receivedDeltaJSONData)
{
    const cJSON *reported = NULL;
    cJSON *jsonDelta = cJSON_Parse(receivedDeltaJSONData);
    cJSON_AddNullToObject(jsonDelta->child, "desired");
    return jsonDelta;
}

void iot_reported(AWS_IoT_Client *mqttClient, char *jsondocumentbuffer)
{
    IoT_Error_t rc = FAILURE;
    char JsonDocumentBuffer[MAX_LENGTH_OF_UPDATE_JSON_BUFFER];
    size_t sizeOfJsonDocumentBuffer = sizeof(JsonDocumentBuffer) / sizeof(JsonDocumentBuffer[0]);
    strcpy(JsonDocumentBuffer, jsondocumentbuffer);
    rc = aws_iot_shadow_update(mqttClient, AWS_IOT_MY_THING_NAME, JsonDocumentBuffer, update_status_callback, NULL, 10, true);
    IOT_DEBUG("%d", rc);
}

char *create_reported_helper(char **data)
{
    char *report_data = NULL, buf[256];
    snprintf(buf, 256, "%s", data);
    cJSON *parse_buf = cJSON_Parse(buf);
    cJSON *report_json_data = cJSON_CreateObject();
    cJSON *state = cJSON_CreateObject();
    cJSON_AddItemToObject(state, "reported", parse_buf);
    cJSON_AddItemToObject(report_json_data, "state", state);
    IOT_DEBUG("%s", cJSON_PrintUnformatted(report_json_data));
    char tempClientTokenBuffer[MAX_SIZE_CLIENT_TOKEN_CLIENT_SEQUENCE];
    if(aws_iot_fill_with_client_token(tempClientTokenBuffer, MAX_SIZE_CLIENT_TOKEN_CLIENT_SEQUENCE) != SUCCESS){
		return false;
	}
    cJSON_AddStringToObject(report_json_data, "clientToken", tempClientTokenBuffer);
    report_data = cJSON_PrintUnformatted(report_json_data);
    exit:
        cJSON_Delete(report_json_data);
        return report_data;
}

static void update_status_callback(const char *pThingName, ShadowActions_t action, Shadow_Ack_Status_t status,
		const char *pReceivedJsonDocument, void *pContextData) {
	IOT_UNUSED(pThingName);
	IOT_UNUSED(action);
	IOT_UNUSED(pReceivedJsonDocument);
	IOT_UNUSED(pContextData);

	if(SHADOW_ACK_TIMEOUT == status) {
		IOT_INFO("Update Timeout--");
	} else if(SHADOW_ACK_REJECTED == status) {
		IOT_INFO("Update RejectedXX");
	} else if(SHADOW_ACK_ACCEPTED == status) {
		IOT_INFO("Update Accepted !!");
	}
}

static bool build_json_for_reported(char *pJsonDocument, size_t maxSizeOfJsonDocument, const char *pReceivedDeltaData, uint32_t lengthDelta) {
	int32_t ret;
	if (NULL == pJsonDocument) {
		return false;
	}
	char tempClientTokenBuffer[MAX_SIZE_CLIENT_TOKEN_CLIENT_SEQUENCE];

	if(aws_iot_fill_with_client_token(tempClientTokenBuffer, MAX_SIZE_CLIENT_TOKEN_CLIENT_SEQUENCE) != SUCCESS){
		return false;
	}
	ret = snprintf(pJsonDocument, maxSizeOfJsonDocument, "{\"state\":{\"desired\":null, \"reported\":%.*s}, \"clientToken\":\"%s\"}", lengthDelta, pReceivedDeltaData, tempClientTokenBuffer);
	if (ret >= maxSizeOfJsonDocument || 0 > ret) {
		return false;
	}
	return true;
}

static IoT_Error_t connect_aws()
{
    IoT_Error_t rc = FAILURE;
    char rootCA[PATH_MAX + 1];
    char clientCRT[PATH_MAX + 1];
    char clientKey[PATH_MAX + 1];
    char CurrentWD[PATH_MAX + 1];
    char JsonDocumentBuffer[MAX_LENGTH_OF_UPDATE_JSON_BUFFER];
    size_t sizeOfJsonDocumentBuffer = sizeof(JsonDocumentBuffer) / sizeof(JsonDocumentBuffer[0]);
    getcwd(CurrentWD, sizeof(CurrentWD));
    snprintf(rootCA, PATH_MAX + 1, "%s/%s/%s", CurrentWD, certDirectory, AWS_IOT_ROOT_CA_FILENAME);
    snprintf(clientCRT, PATH_MAX + 1, "%s/%s/%s", CurrentWD, certDirectory, AWS_IOT_CERTIFICATE_FILENAME);
    snprintf(clientKey, PATH_MAX + 1, "%s/%s/%s", CurrentWD, certDirectory, AWS_IOT_PRIVATE_KEY_FILENAME);
    ShadowInitParameters_t sp = ShadowInitParametersDefault;
    sp.pHost = AWS_IOT_MQTT_HOST;
    sp.port = AWS_IOT_MQTT_PORT;
    sp.pClientCRT = clientCRT;
    sp.pClientKey = clientKey;
    sp.pRootCA = rootCA;
    sp.enableAutoReconnect = false;
    sp.disconnectHandler = NULL;
    aws_iot_shadow_init(&mqttClient, &sp);
    ShadowConnectParameters_t scp = ShadowConnectParametersDefault;
    scp.pMyThingName = AWS_IOT_MY_THING_NAME;
    scp.pMqttClientId = AWS_IOT_MQTT_CLIENT_ID;
    scp.mqttClientIdLen = (uint16_t) strlen(AWS_IOT_MQTT_CLIENT_ID);
    rc = aws_iot_shadow_connect(&mqttClient, &scp);
    return rc;
}

void *aws_iot_register()
{
    deltaObject.pData = stringToEchoDelta;
    deltaObject.dataLength = SHADOW_MAX_SIZE_OF_RX_BUFFER;
    deltaObject.pKey = "state";
    deltaObject.type = SHADOW_JSON_OBJECT;
    deltaObject.cb = delta_callback;
    aws_iot_shadow_register_delta(&mqttClient, &deltaObject);
    while (1) {
        aws_iot_shadow_yield(&mqttClient, 200);
        if (messageArrivedOnDelta) {
            connect_socket();
            int ret;
            ret = send(sock_fd, stringToEchoDelta, SHADOW_MAX_SIZE_OF_RX_BUFFER, 0);
            if (ret >= 0)
            {
                aws_iot_shadow_update(&mqttClient, AWS_IOT_MY_THING_NAME, stringToEchoDelta, update_status_callback, NULL, 2, true);
                close(sock_fd);
                messageArrivedOnDelta = false;
            }
        }
        else if (!messageArrivedOnDelta)
        {
            sock_server();
        }
    }
}
