/********************************** (C) COPYRIGHT *******************************
 * File Name          : Main.c
 * Author             : WCH
 * Version            : V1.0
 * Date               : 2020/08/06
 * Description        : ����1�շ���ʾ
 *********************************************************************************
 * Copyright (c) 2021 Nanjing Qinheng Microelectronics Co., Ltd.
 * Attention: This software (modified or not) and binary are used for 
 * microcontroller manufactured by Nanjing Qinheng Microelectronics.
 *******************************************************************************/

#include "ps4_driver.h"
#include "CH58x_common.h"

#include <rtthread.h>
ALIGN(RT_ALIGN_SIZE)
static char rsa_sign_stack[2048];
static struct rt_thread rsa_sign_thread;

static char usb_hid_stack[2048];
static struct rt_thread usb_hid_thread;

#define USB_BUSID 0x00
#define USB_BASE_ADDER 0x40008400u

typedef struct __attribute((packed, aligned(1)))
{
    uint8_t report_id;
    uint8_t buttons1;
    uint8_t buttons2;
    uint8_t buttons3;
    int8_t lx;
    int8_t ly;
    int8_t rx;
    int8_t ry;
    uint8_t rt;
    uint8_t lt;
    uint8_t _reserved[6];
} InputReport;


//static uint8_t recv_buf[REPORT_PKT_SIZE];
__attribute__((aligned(4))) uint8_t RxBuffer[MAX_PACKET_SIZE]; // IN, must even address
__attribute__((aligned(4))) uint8_t TxBuffer[MAX_PACKET_SIZE]; // OUT, must even address

void task_rsa_sign(void* parameter) {

    while(1){

        ps4_driver_process();
        rt_thread_delay(500);
    }
}

void task_usb_hid(void* parameter)
{
    rt_kprintf("task_usb_hid thread\n");
    uint8_t i, s, k, len, endp;
    uint16_t  loc;
    hid_ps4_report_t ps4_report;

    GPIOB_SetBits(GPIO_Pin_4);
    GPIOB_ModeCfg(GPIO_Pin_4, GPIO_ModeOut_PP_5mA);

    rt_kprintf("Start @ChipID=%02X\n", R8_CHIP_ID);

    ps4_driver_init(USB_BUSID,USB_BASE_ADDER);

    rt_kprintf("ps4_driver_init done\n");

    memset(&ps4_report,0,sizeof(hid_ps4_report_t));
    ps4_report.report_id=0x1;
    ps4_report.battery = 0 | (1 << 4) | 11;

    ps4_report.gyrox = 0;
    ps4_report.gyroy = 0;
    ps4_report.gyroz = 0;
    ps4_report.accelx = 0;
    ps4_report.accely = 0;
    ps4_report.accelz = 0;

    ps4_report.extension = 0x01;

    ps4_report.touchpad_event_active = 0;
    ps4_report.touchpad_counter = 0;
    ps4_report.touchpad1_touches = (1 << 7);
    ps4_report.touchpad2_touches = (1 << 7);

    ps4_report.unknown3[1] = 0x80;
    ps4_report.unknown3[5] = 0x80;
    ps4_report.unknown3[10] = 0x80;
    ps4_report.unknown3[14] = 0x80;
    ps4_report.unknown3[19] = 0x80;


    pU2HOST_RX_RAM_Addr = RxBuffer;
    pU2HOST_TX_RAM_Addr = TxBuffer;

    USB2_HostInit();
    rt_kprintf("Wait Device In\n");

    while(1){

        s = ERR_SUCCESS;
        if(R8_USB2_INT_FG & RB_UIF_DETECT)
        { // �����USB��������ж�����
            R8_USB2_INT_FG = RB_UIF_DETECT;
            s = AnalyzeRootU2Hub();
            if(s == ERR_USB_CONNECT)
                FoundNewU2Dev = 1;
        }

        if(FoundNewU2Dev || s == ERR_USB_CONNECT)
        { // ���µ�USB�豸����
            FoundNewU2Dev = 0;
            mDelaymS(200);          // ����USB�豸�ղ�����δ�ȶ�,�ʵȴ�USB�豸���ٺ���,������ζ���
            s = InitRootU2Device(); // ��ʼ��USB�豸
            if(s != ERR_SUCCESS)
            {
                rt_kprintf("EnumAllRootDev err = %02X\n", (uint16_t)s);
            }
        }

        /* ����¶����ӵ���HUB������ö��HUB */
        s = EnumAllU2HubPort(); // ö������ROOT-HUB�˿����ⲿHUB��Ķ���USB�豸
        if(s != ERR_SUCCESS)
        { // ������HUB�Ͽ���
            rt_kprintf("EnumAllHubPort err = %02X\n", (uint16_t)s);
        }
       // ps4_driver_process();

        /* ����豸�Ǽ��� */
        loc = U2SearchTypeDevice(DEV_TYPE_GAMEPAD); // ��ROOT-HUB�Լ��ⲿHUB���˿�������ָ�����͵��豸���ڵĶ˿ں�
        if(loc != 0xFFFF)
        { // �ҵ���,���������KeyBoard��δ���?
            i = (uint8_t)(loc >> 8);
            len = (uint8_t)loc;
            SelectU2HubPort(len);                                                 // ѡ�����ָ����ROOT-HUB�˿�,���õ�ǰUSB�ٶ��Լ��������豸��USB��ַ
            endp = len ? DevOnU2HubPort[len - 1].GpVar[0] : ThisUsb2Dev.GpVar[0]; // �ж϶˵�ĵ�ַ,λ7����ͬ����־λ
            if(endp & USB_ENDP_ADDR_MASK)
            {                                                                                                        // �˵���Ч
                s = USB2HostTransact(USB_PID_IN << 4 | endp & 0x7F, endp & 0x80 ? RB_UH_R_TOG | RB_UH_T_TOG : 0, 0); // ��������,��ȡ����,NAK������
                if(s == ERR_SUCCESS)
                {
                    endp ^= 0x80; // ͬ����־��ת
                    if(len)
                        DevOnU2HubPort[len - 1].GpVar[0] = endp; // ����ͬ����־λ
                    else
                        ThisUsb2Dev.GpVar[0] = endp;
                    len = R8_USB2_RX_LEN; // ���յ������ݳ���
                    if(len)
                    {


                        /*rt_kprintf("keyboard data: ");
                        for(i = 0; i < len; i++)
                        {
                            rt_kprintf("x%02X ", (uint16_t)(RxBuffer[i]));
                        }
                        rt_kprintf("\n");
                         */

                        InputReport* xinput=(InputReport*)RxBuffer;
                        ps4_report.lt=xinput->lt;
                        ps4_report.rt=xinput->rt;
                        ps4_report.lx=xinput->lx;
                        ps4_report.ly=xinput->ly;
                        ps4_report.rx=xinput->rx;
                        ps4_report.ry=xinput->ry;

                        ps4_report.button_home=xinput->buttons2&0x10? 1:0;

                        ps4_report.button_north=xinput->buttons1& 0x10? 1:0;  //y
                        ps4_report.button_east=xinput->buttons1& 0x02 ? 1:0;   //b
                        ps4_report.button_south=xinput->buttons1& 0x01? 1:0;  //a
                        ps4_report.button_west=xinput->buttons1& 0x08 ? 1:0;   //x


                        ps4_report.button_select=xinput->buttons2& 0x04? 1:0;
                        ps4_report.button_l3=xinput->buttons2& 0x20? 1:0;
                        ps4_report.button_r3=xinput->buttons2& 0x40? 1:0;
                        ps4_report.button_start=xinput->buttons2& 0x08? 1:0;

                        //������ť todo
                        ps4_report.button_touchpad=0;
                        ps4_report.touchpad1_touches = (1 << 7);
                        ps4_report.touchpad1_position[0]=0;
                        ps4_report.touchpad1_position[1]=0;
                        ps4_report.touchpad1_position[2]=0;

                        if(xinput->buttons1& 0x04){

                            //touchpad resolution = 1920x942
                            //480 x 471
                            ps4_report.button_touchpad=1;
                            ps4_report.touchpad1_touches=1;
                            ps4_report.touchpad1_position[0]=0xE0;
                            ps4_report.touchpad1_position[1]=0x71;
                            ps4_report.touchpad1_position[2]=0x1D;

                        }
                        if(xinput->buttons1& 0x20){

                            ps4_report.button_touchpad=1;
                            ps4_report.touchpad1_touches=1;

                            //1440 x 471
                            ps4_report.touchpad1_position[0]=0xA0;
                            ps4_report.touchpad1_position[1]=0x75;
                            ps4_report.touchpad1_position[2]=0x1D;
                        }


                        if(xinput->buttons3==0x0f){
                            ps4_report.dpad= 0x08;
                        }else{
                            ps4_report.dpad= xinput->buttons3;
                        }

                        ps4_report.button_l2=xinput->buttons2& 0x01? 1:0;
                        ps4_report.button_r2=xinput->buttons2& 0x02? 1:0;
                        ps4_report.button_l1=xinput->buttons1& 0x40? 1:0;
                        ps4_report.button_r1=xinput->buttons1& 0x80? 1:0;

                        ps4_driver_report(USB_BUSID,&ps4_report);

                        GPIOB_InverseBits(GPIO_Pin_4);
                    }
                }
                else if(s != (USB_PID_NAK | ERR_USB_TRANSFER))
                {
                    rt_kprintf("keyboard error %02x\n", (uint16_t)s); // �����ǶϿ���
                }
            }
            else
            {
                rt_kprintf("keyboard no interrupt endpoint\n");
            }
            SetUsb2Speed(1); // Ĭ��Ϊȫ��
        }
        //With USB connection, data is updated at approximately 4-ms frequencies (250 times/second).
        rt_thread_mdelay(4);

    }

}


int main(void){

    rt_kprintf("main start\n");

    rt_enter_critical();

    rt_thread_init(&usb_hid_thread,
                        "usb",
                        task_usb_hid,
                        RT_NULL,
                        &usb_hid_stack[0],
                        sizeof(usb_hid_stack),
                        3, 20);

    rt_thread_startup(&usb_hid_thread);


    rt_thread_init(&rsa_sign_thread,
                        "rsa",
                        task_rsa_sign,
                        RT_NULL,
                        &rsa_sign_stack[0],
                        sizeof(rsa_sign_stack),
                        5, 10);

    rt_thread_startup(&rsa_sign_thread);

    rt_exit_critical();

    rt_kprintf("done\n");
}
