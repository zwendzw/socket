# socket with aws iot

Environment
===
gcc host ``` arm-*-eabi ```

Usage
===
change config
```src/libs/aws-iot-device-sdk-embedded-C/include/aws_iot_config.h```

replace your config
```
#define AWS_IOT_MQTT_HOST
#define AWS_IOT_MQTT_PORT
#define AWS_IOT_MQTT_CLIENT_ID
#define AWS_IOT_MY_THING_NAME
#define AWS_IOT_ROOT_CA_FILENAME
#define AWS_IOT_CERTIFICATE_FILENAME
#define AWS_IOT_PRIVATE_KEY_FILENAME
```

