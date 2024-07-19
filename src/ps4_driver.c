/*
 * ps4_driver.c
 *
 *  Created on: 2024年7月7日
 *      Author: jiang
 */
#include "ps4_driver.h"


#include "usbd_core.h"
#include "usbd_hid.h"
#include "CH58x_common.h"

#include "mbedtls/rsa.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "crc32.h"
#include "rtthread.h"

#define PS4_KEEPALIVE_TIMER 5

void usb_dc_low_level_init(void)
{
    extern void USB_IRQHandler(void);
    PFIC_EnableIRQ(USB_IRQn);
    PFIC_EnableFastINT0(USB_IRQn, (uint32_t)(void *)USB_IRQHandler);
}


const uint8_t ps4_serial[0x10] = {0};
const uint8_t ps4_signature[0x100] = {0};
const uint8_t ps4_key_N[256] = {0
};
const uint8_t ps4_key_E[4] = {0x00, 0x01, 0x00, 0x01};
const uint8_t ps4_key_D[256] = {0
};

const uint8_t ps4_key_P[128] = {0
};
const uint8_t ps4_key_Q[128] = {0
};

static const uint8_t ps4_0x03_report[] = {
    0x03, 0x21, 0x27, 0x04, 0xcf, 0x00, 0x2c, 0x56,
    0x08, 0x00, 0x3d, 0x00, 0xe8, 0x03, 0x04, 0x00,
    0xff, 0x7f, 0x0d, 0x0d, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

};

const uint8_t ps4_output_0xf3[] = {0xf3, 0x0, 0x38, 0x38, 0, 0, 0, 0};

int rng(void*p_rng, unsigned char* p, size_t len) {
    (void) p_rng;
    p[0] = rand();
    return 0;
};


typedef enum
{
    no_nonce = 0,
    receiving_nonce = 1,
    nonce_ready = 2,
    signed_nonce_ready = 3
} PS4State;

typedef enum
{
    PS4_UNKNOWN_0X03 = 0x03,        // Unknown (PS4 Report 0x03)
    PS4_SET_AUTH_PAYLOAD = 0xF0,    // Set Auth Payload
    PS4_GET_SIGNATURE_NONCE = 0xF1, // Get Signature Nonce
    PS4_GET_SIGNING_STATE = 0xF2,   // Get Signing State
    PS4_RESET_AUTH = 0xF3           // Unknown (PS4 Report 0xF3)
} PS4AuthReport;

static PS4State ps4_auth_state;
static uint8_t ps4_auth_buffer[1064];
static uint8_t ps4_auth_nonce_buffer[256];
static uint8_t cur_nonce_id = 1;
static uint8_t send_nonce_part = 0;

USB_NOCACHE_RAM_SECTION USB_MEM_ALIGNX uint8_t last_report[64];

static uint8_t hashed_nonce[32];

static uint8_t report_counter = 0;
static uint32_t axis_timing=0;
static uint32_t last_report_timer = 0;

static mbedtls_rsa_context pk;
static rt_mutex_t usb_report_mutex = RT_NULL;

void rsa_init(void){

    int ret;
    mbedtls_rsa_init(&pk);
    mbedtls_rsa_set_padding(&pk, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    ret = mbedtls_rsa_import_raw(&pk, ps4_key_N, 256, ps4_key_P, 128, ps4_key_Q,
                                 128, ps4_key_D, 256, ps4_key_E, 4);

    ret = mbedtls_rsa_complete(&pk);

    if (ret) {
        rt_kprintf("mbedtls_rsa_complete failed\n");

    }

    if ((ret = mbedtls_rsa_check_privkey(&pk)) != 0)
        {
        rt_kprintf(" failed\n  ! mbedtls_rsa_check_privkey failed with -0x%0x\n",
                   (unsigned int)-ret);
        }
    rt_kprintf("rsa_init done\n");
}

void sign_nonce(void) {

    if(ps4_auth_state==nonce_ready)
    {
        int ret;
        //rt_kprintf("task_rsa_sign start sign\n");
        if (mbedtls_sha256(ps4_auth_nonce_buffer, 256, hashed_nonce, 0) <
                0) {
            rt_kprintf("mbedtls_sha256 failed\n");
        }
        ret =
            mbedtls_rsa_rsassa_pss_sign(&pk, rng, NULL, MBEDTLS_MD_SHA256,
                                        32, hashed_nonce, ps4_auth_buffer);
        if (ret < 0) {
            rt_kprintf("mbedtls_rsa_rsassa_pss_sign failed code:%08x\n",-ret);
        }

        int offset = 256;
        memcpy(&ps4_auth_buffer[offset], ps4_serial, 16);
        offset += 16;
        mbedtls_rsa_export_raw(
                        &pk,
                        &ps4_auth_buffer[offset], 256,
                        NULL, 0,
                        NULL, 0,
                        NULL, 0,
                        &ps4_auth_buffer[offset+256], 256
                    );
        offset += 512;
        memcpy(&ps4_auth_buffer[offset], ps4_signature, 256);
        offset += 256;
        memset(&ps4_auth_buffer[offset], 0, 24);

        //rt_kprintf("task_rsa_sign sign done\n");

        ps4_auth_state = signed_nonce_ready;
    }

}


/*********************************************************************
 * @fn      task1_entry
 *
 * @brief   task1任务函数
 *
 * @return  none
 */

//__attribute__((aligned(4))) uint8_t RxBuffer[MAX_PACKET_SIZE]; // IN, must even address
//__attribute__((aligned(4))) uint8_t TxBuffer[MAX_PACKET_SIZE]; // OUT, must even address


/*********************************************************************
 * @fn      main
 *
 * @brief   主函数
 *
 * @return  none
 */
/*!< hidraw in endpoint */
#define HIDRAW_IN_EP       0x81
#define HIDRAW_IN_EP_SIZE  64
#define HIDRAW_IN_INTERVAL 5

#define HIDRAW_OUT_EP          0x02
#define HIDRAW_OUT_EP_SIZE     64
#define HIDRAW_OUT_EP_INTERVAL 5

#define USBD_LANGID_STRING 1033

#define LSB(n) (n & 255)
#define MSB(n) ((n >> 8) & 255)

#define PS4_VENDOR_ID 0x054c
#define PS4_PRODUCT_ID 0x0ce6

const uint8_t ps4_desc_hid_report[] = {
    0x05, 0x01,       // Usage Page (Generic Desktop Ctrls)
    0x09, 0x05,       // Usage (Game Pad)
    0xA1, 0x01,       // Collection (Application)
    0x85, 0x01,       //   Report ID (1)
    0x09, 0x30,       //   Usage (X)
    0x09, 0x31,       //   Usage (Y)
    0x09, 0x32,       //   Usage (Z)
    0x09, 0x35,       //   Usage (Rz)
    0x15, 0x00,       //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08,       //   Report Size (8)
    0x95, 0x04,       //   Report Count (4)
    0x81, 0x02,       //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)

    0x09, 0x39,       //   Usage (Hat switch)
    0x15, 0x00,       //   Logical Minimum (0)
    0x25, 0x07,       //   Logical Maximum (7)
    0x35, 0x00,       //   Physical Minimum (0)
    0x46, 0x3B, 0x01, //   Physical Maximum (315)
    0x65, 0x14,       //   Unit (System: English Rotation, Length: Centimeter)
    0x75, 0x04,       //   Report Size (4)
    0x95, 0x01,       //   Report Count (1)
    0x81, 0x42,       //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,Null State)

    0x65, 0x00, //   Unit (None)
    0x05, 0x09, //   Usage Page (Button)
    0x19, 0x01, //   Usage Minimum (0x01)
    0x29, 0x0E, //   Usage Maximum (0x0E)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x01, //   Logical Maximum (1)
    0x75, 0x01, //   Report Size (1)
    0x95, 0x0E, //   Report Count (14)
    0x81, 0x02, //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)

    0x06, 0x00, 0xFF, //   Usage Page (Vendor Defined 0xFF00)
    0x09, 0x20,       //   Usage (0x20)
    0x75, 0x06,       //   Report Size (6)
    0x95, 0x01,       //   Report Count (1)
    0x81, 0x02,       //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)

    0x05, 0x01,       //   Usage Page (Generic Desktop Ctrls)
    0x09, 0x33,       //   Usage (Rx)
    0x09, 0x34,       //   Usage (Ry)
    0x15, 0x00,       //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08,       //   Report Size (8)
    0x95, 0x02,       //   Report Count (2)
    0x81, 0x02,       //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)

    0x06, 0x00, 0xFF, //   Usage Page (Vendor Defined 0xFF00)
    0x09, 0x21,       //   Usage (0x21)
    0x95, 0x36,       //   Report Count (54)
    0x81, 0x02,       //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)

    0x85, 0x05, //   Report ID (5)
    0x09, 0x22, //   Usage (0x22)
    0x95, 0x1F, //   Report Count (31)
    0x91, 0x02, //   Output (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)

    0x85, 0x03,       //   Report ID (3)
    0x0A, 0x21, 0x27, //   Usage (0x2721)
    0x95, 0x2F,       //   Report Count (47)
    0xB1, 0x02,       //   Feature (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0xC0,             // End Collection

    0x06, 0xF0, 0xFF, // Usage Page (Vendor Defined 0xFFF0)
    0x09, 0x40,       // Usage (0x40)
    0xA1, 0x01,       // Collection (Application)
    0x85, 0xF0,       //   Report ID (-16) AUTH F0
    0x09, 0x47,       //   Usage (0x47)
    0x95, 0x3F,       //   Report Count (63)
    0xB1, 0x02,       //   Feature (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0x85, 0xF1,       //   Report ID (-15) AUTH F1
    0x09, 0x48,       //   Usage (0x48)
    0x95, 0x3F,       //   Report Count (63)
    0xB1, 0x02,       //   Feature (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0x85, 0xF2,       //   Report ID (-14) AUTH F2
    0x09, 0x49,       //   Usage (0x49)
    0x95, 0x0F,       //   Report Count (15)
    0xB1, 0x02,       //   Feature (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0x85, 0xF3,       //   Report ID (-13) Auth F3 (Reset)
    0x0A, 0x01, 0x47, //   Usage (0x4701)
    0x95, 0x07,       //   Report Count (7)
    0xB1, 0x02,       //   Feature (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0xC0,             // End Collection
};

/*!< global descriptor */
#define CONFIG1_DESC_SIZE (9 + 9 + 9 + 7 + 7)
const uint8_t ps4_desc_cfg[] =
    {
    0x12,             // bLength
    USB_DESCRIPTOR_TYPE_DEVICE,                // bDescriptorType
    0x00, 0x02,                   // bcdUSB
    0,                // bDeviceClass
    0,                // bDeviceSubClass
    0,                // bDeviceProtocol
    0x40,               // bMaxPacketSize0
    LSB(PS4_VENDOR_ID), MSB(PS4_VENDOR_ID),   // idVendor
    LSB(PS4_PRODUCT_ID), MSB(PS4_PRODUCT_ID), // idProduct
    0x00, 0x01,                   // bcdDevice
    1,                // iManufacturer
    2,                // iProduct
    0,                // iSerialNumber
    1,                 // bNumConfigurations

        // configuration descriptor, USB spec 9.6.3, page 264-266, Table 9-10
    0x09,          // bLength;
    USB_DESCRIPTOR_TYPE_CONFIGURATION,    // bDescriptorType;
    LSB(CONFIG1_DESC_SIZE), // wTotalLength
    MSB(CONFIG1_DESC_SIZE),
    1,               // bNumInterfaces
    1,               // bConfigurationValue
    0,               // iConfiguration
    0x80,            // bmAttributes
    50,              // bMaxPower

                 // interface descriptor, USB spec 9.6.5, page 267-269, Table 9-12
    0x09,               // bLength
    USB_DESCRIPTOR_TYPE_INTERFACE,               // bDescriptorType
    0,               // bInterfaceNumber
    0,               // bAlternateSetting
    0x02,               // bNumEndpoints
    0x03,            // bInterfaceClass (0x03 = HID)
    0x00,            // bInterfaceSubClass (0x00 = No Boot)
    0x00,            // bInterfaceProtocol (0x00 = No Protocol)
    0x00,            // iInterface
                 // HID interface descriptor, HID 1.11 spec, section 6.2.1
    0x09,               // bLength
    HID_DESCRIPTOR_TYPE_HID,            // bDescriptorType
    0x11, 0x01,      // bcdHID
    0,               // bCountryCode
    0x01,            // bNumDescriptors
    0x22,            // bDescriptorType
    sizeof(ps4_desc_hid_report), // wDescriptorLength
    0x00,

            // endpoint descriptor, USB spec 9.6.6, page 269-271, Table 9-13
    0x07,        // bLength
    USB_DESCRIPTOR_TYPE_ENDPOINT,  // bDescriptorType
    HIDRAW_IN_EP, // bEndpointAddress
    0x03,     // bmAttributes (0x03=intr)
    WBVAL(HIDRAW_IN_EP_SIZE),    // wMaxPacketSize
    HIDRAW_IN_INTERVAL,         // bInterval (1 ms)

    0x07,        // bLength
    USB_DESCRIPTOR_TYPE_ENDPOINT,  // bDescriptorType
    HIDRAW_OUT_EP, // bEndpointAddress
    0x03,     // bmAttributes (0x03=intr)
    WBVAL(HIDRAW_OUT_EP_SIZE),    // wMaxPacketSize
    HIDRAW_OUT_EP_INTERVAL,         // bInterval (1 ms)

             /*
    * string0 descriptor
            */
    USB_LANGID_INIT(USBD_LANGID_STRING),
            /*
     * string1 descriptor
     */
    0x38,           /* bLength */
    USB_DESCRIPTOR_TYPE_STRING, /* bDescriptorType */
    'S', 0x00,      /* wcChar0 */
    'o', 0x00,      /* wcChar1 */
    'n', 0x00,      /* wcChar2 */
    'y', 0x00,      /* wcChar3 */
    ' ', 0x00,      /* wcChar4 */
    'C', 0x00,      /* wcChar5 */
    'o', 0x00,      /* wcChar6 */
    'm', 0x00,      /* wcChar7 */
    'p', 0x00,      /* wcChar8 */
    'u', 0x00,      /* wcChar9 */
    't', 0x00,      /* wcChar10 */
    'e', 0x00,      /* wcChar11 */
    'r', 0x00,      /* wcChar12 */
    ' ', 0x00,      /* wcChar13 */
    'E', 0x00,      /* wcChar14 */
    'n', 0x00,      /* wcChar15 */
    't', 0x00,      /* wcChar16 */
    'e', 0x00,      /* wcChar17 */
    'r', 0x00,      /* wcChar18 */
    't', 0x00,      /* wcChar19 */
    'a', 0x00,      /* wcChar20 */
    'i', 0x00,      /* wcChar21 */
    'n', 0x00,      /* wcChar22 */
    'm', 0x00,      /* wcChar23 */
    'e', 0x00,      /* wcChar24 */
    'n', 0x00,      /* wcChar25 */
    't', 0x00,      /* wcChar26 */
    /*
     * string2 descriptor
     */
    0x28,           /* bLength */
    USB_DESCRIPTOR_TYPE_STRING, /* bDescriptorType */
    'W', 0x00,      /* wcChar0 */
    'i', 0x00,      /* wcChar1 */
    'r', 0x00,      /* wcChar2 */
    'e', 0x00,      /* wcChar3 */
    'l', 0x00,      /* wcChar4 */
    'e', 0x00,      /* wcChar5 */
    's', 0x00,      /* wcChar6 */
    's', 0x00,      /* wcChar7 */
    ' ', 0x00,      /* wcChar8 */
    'C', 0x00,      /* wcChar9 */
    'o', 0x00,      /* wcChar10 */
    'n', 0x00,      /* wcChar11 */
    't', 0x00,      /* wcChar12 */
    'r', 0x00,      /* wcChar13 */
    'o', 0x00,      /* wcChar14 */
    'l', 0x00,      /* wcChar15 */
    'l', 0x00,      /* wcChar16 */
    'e', 0x00,      /* wcChar17 */
    'r', 0x00,      /* wcChar18 */
    /*
     * string3 descriptor
     */
    0xE,           /* bLength */
    USB_DESCRIPTOR_TYPE_STRING, /* bDescriptorType */
    '1', 0x00,      /* wcChar0 */
    '2', 0x00,      /* wcChar1 */
    '3', 0x00,      /* wcChar2 */
    '4', 0x00,      /* wcChar3 */
    '5', 0x00,      /* wcChar4 */
    '6', 0x00,      /* wcChar5 */

    0x00
};


#define HID_STATE_IDLE 0
#define HID_STATE_BUSY 1

/*!< hid state ! Data can be sent only when state is idle  */
static volatile uint8_t custom_state;

void usbd_event_handler(uint8_t busid, uint8_t event)
{
    switch (event) {
        case USBD_EVENT_RESET:
            break;
        case USBD_EVENT_CONNECTED:
            break;
        case USBD_EVENT_DISCONNECTED:
            break;
        case USBD_EVENT_RESUME:
            break;
        case USBD_EVENT_SUSPEND:
            break;
        case USBD_EVENT_CONFIGURED:
            break;
        case USBD_EVENT_SET_REMOTE_WAKEUP:
            break;
        case USBD_EVENT_CLR_REMOTE_WAKEUP:
            break;
        default:
            break;
    }
}

static void usbd_hid_custom_in_callback(uint8_t busid, uint8_t ep, uint32_t nbytes)
{
    //PRINT("actual in len:%d\r\n", nbytes);
    custom_state = HID_STATE_IDLE;
}

static void usbd_hid_custom_out_callback(uint8_t busid,uint8_t ep, uint32_t nbytes)
{
    //PRINT("actual out len:%d\r\n", nbytes);

}


static struct usbd_endpoint custom_in_ep = {
    .ep_cb = usbd_hid_custom_in_callback,
    .ep_addr = HIDRAW_IN_EP
};

static struct usbd_endpoint custom_out_ep = {
    .ep_cb = usbd_hid_custom_out_callback,
    .ep_addr = HIDRAW_OUT_EP
};

void save_nonce(uint8_t nonce_id, uint8_t nonce_page, uint8_t *buffer, uint16_t buflen)
{

    if (nonce_page != 0 && nonce_id != cur_nonce_id)
    {
        ps4_auth_state = no_nonce;
        return; // setting nonce with mismatched id
    }

    memcpy(&ps4_auth_nonce_buffer[nonce_page * 56], buffer, buflen);
    if (nonce_page == 4)
    {
        ps4_auth_state = nonce_ready;

    }
    else if (nonce_page == 0)
    {
        cur_nonce_id = nonce_id;
        ps4_auth_state = receiving_nonce;
    }
}

void usbd_hid_get_report(uint8_t busid, uint8_t intf, uint8_t report_id, uint8_t report_type, uint8_t **report_data, uint32_t *len){

    rt_mutex_take(usb_report_mutex, RT_WAITING_FOREVER);

    if (report_type == HID_REPORT_INPUT){

        //rt_kprintf("usbd_hid_get_report HID_REPORT_INPUT report_id:%d\n",report_id);

        memcpy(report_data[0], last_report, sizeof(hid_ps4_report_t));
        *len=sizeof(hid_ps4_report_t);

    }else if(report_type == HID_REPORT_FEATURE){

        //rt_kprintf("usbd_hid_get_report HID_REPORT_FEATURE report_id:%d\n",report_id);

        uint8_t* data= report_data[0];
        uint32_t crc32 = 0;
        switch (report_id){
        case PS4_UNKNOWN_0X03:
            memcpy(report_data[0], ps4_0x03_report, sizeof(ps4_0x03_report));
            *len=sizeof(ps4_0x03_report);
            break;
        case PS4_GET_SIGNATURE_NONCE:
            //rt_kprintf("PS4_GET_SIGNATURE_NONCE reqlen:%d\n",*len);
            data[0] = 0xF1;
            data[1] = cur_nonce_id;
            data[2] = send_nonce_part;
            data[3] = 0;

            memcpy(&data[4], &ps4_auth_buffer[send_nonce_part * 56], 56);
            crc32 = crc32_le(crc32, data, 60);
            memcpy(&data[60], &crc32, sizeof(uint32_t));
            if ((++send_nonce_part) == 19){
                ps4_auth_state = no_nonce;
                send_nonce_part = 0;
            }
            *len=64;
            break;
        case PS4_GET_SIGNING_STATE:
            //rt_kprintf("PS4_GET_SIGNING_STATE reqlen:%d\n",*len);

            data[0] = 0xF2;
            data[1] = cur_nonce_id;
            data[2] = ps4_auth_state == signed_nonce_ready ? 0 : 16;
            memset(&data[3], 0, 9);
            crc32 = crc32_le(crc32, data, 12);
            memcpy(&data[12], &crc32, sizeof(uint32_t));
            *len=16;
            break;

        case PS4_RESET_AUTH:

            if (*len != sizeof(ps4_output_0xf3)){
                *len=0;
            }else{
                ps4_auth_state = no_nonce;
                memcpy(report_data[0], ps4_output_0xf3, sizeof(ps4_output_0xf3));
                *len=sizeof(ps4_output_0xf3);
            }
            break;
        }
    }

    rt_mutex_release(usb_report_mutex);
}


void usbd_hid_set_report(uint8_t busid, uint8_t intf, uint8_t report_id, uint8_t report_type, uint8_t *report, uint32_t report_len){

    //rt_kprintf("usbd_hid_set_report report_len:%d\n",report_len);

    uint8_t nonce_id;
    uint8_t nonce_page;
    uint32_t crc32 = 0;

    uint8_t nonce[56];
    uint16_t noncelen;

    rt_mutex_take(usb_report_mutex, RT_WAITING_FOREVER);

    if(report_type==HID_REPORT_FEATURE ){

        if(report_id == PS4_SET_AUTH_PAYLOAD){

            if (report_len != 64){
                return ;
            }

            nonce_id = report[1];
            nonce_page = report[2];
            crc32 = crc32_le(crc32, report, report_len - sizeof(uint32_t));
            if (crc32 != *((unsigned int *)&report[report_len - sizeof(uint32_t)])){
                rt_kprintf("CRC32 failed on set report\n");
                return; // CRC32 failed on set report
            }
            if (nonce_page == 4){

                noncelen = 32; // from 4 to 64 - 24 - 4
            }else{

                noncelen = 56;
            }

            memcpy(nonce, &report[4], noncelen);
            save_nonce(nonce_id, nonce_page, nonce, noncelen);
        }

    }

    rt_mutex_release(usb_report_mutex);
}

/* function ------------------------------------------------------------------*/
/**
 * @brief            hid custom init
 * @pre              none
 * @param[in]        none
 * @retval           none
 */
struct usbd_interface intf0;



void ps4_driver_init(uint8_t busid, uint32_t reg_base)
{

    rsa_init();

    usbd_desc_register(busid ,ps4_desc_cfg);
    usbd_add_interface(busid, usbd_hid_init_intf(busid, &intf0, ps4_desc_hid_report, sizeof(ps4_desc_hid_report)));
    usbd_add_endpoint(busid, &custom_in_ep);
    usbd_add_endpoint(busid, &custom_out_ep);

    usbd_initialize(busid, reg_base, usbd_event_handler);

    ps4_auth_state = no_nonce;
    usb_report_mutex = rt_mutex_create("usb_report", RT_IPC_FLAG_FIFO);

}


void ps4_driver_process(){

    sign_nonce();

}

void ps4_driver_report(uint8_t busid,hid_ps4_report_t * ps4_report){

    rt_mutex_take(usb_report_mutex, RT_WAITING_FOREVER);
    uint32_t now=rt_tick_get();

    ps4_report->timestamp = axis_timing;
    ps4_report->report_counter =report_counter;

    if (memcmp(last_report, ps4_report, sizeof(hid_ps4_report_t)) != 0){

        memcpy(last_report, ps4_report, sizeof(hid_ps4_report_t));
        usbd_ep_start_write(busid, HIDRAW_IN_EP, last_report, sizeof(hid_ps4_report_t));
        last_report_timer = now;

    }else{

        if ((now - last_report_timer) > PS4_KEEPALIVE_TIMER) {
            report_counter = (report_counter+1) & 0x3F;
            axis_timing = now;
        }

    }

    rt_mutex_release(usb_report_mutex);

}

