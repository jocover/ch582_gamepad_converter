/*
 * ps4_driver.h
 *
 *  Created on: 2024Äê7ÔÂ5ÈÕ
 *      Author: user
 */

#ifndef SRC_PS4_DRIVER_H_
#define SRC_PS4_DRIVER_H_

#include <stdint.h>

 typedef struct __attribute((packed, aligned(1))) {
    uint8_t report_id;//0
    uint8_t lx;//1
    uint8_t ly;//2
    uint8_t rx;//3
    uint8_t ry;//4
    // 4 bits for the d-pad.
    uint8_t dpad : 4;

    // 14 bits for buttons.
    uint8_t button_west : 1;
    uint8_t button_south : 1;
    uint8_t button_east : 1;
    uint8_t button_north : 1;

    uint8_t button_l1 : 1;
    uint8_t button_r1 : 1;
    uint8_t button_l2 : 1;
    uint8_t button_r2 : 1;
    uint8_t button_select : 1;
    uint8_t button_start : 1;
    uint8_t button_l3 : 1;
    uint8_t button_r3 : 1;

    uint8_t button_home : 1;
    uint8_t button_touchpad : 1;
    uint8_t report_counter : 6;

    uint8_t lt;//8
    uint8_t rt;//9
    uint16_t timestamp;//10-11
    uint8_t battery;//12
    uint16_t gyrox;//13-14
    uint16_t gyroy;//15-16
    uint16_t gyroz;//17-18
    int16_t accelx;//19-20
    int16_t accely;//21-22
    int16_t accelz;//23-24
    uint8_t unknown1[5];//25-29
    uint8_t extension;//30
    uint8_t unknown2[2];//31-32
    uint8_t touchpad_event_active;//33
    uint8_t touchpad_counter;//34
    uint8_t touchpad1_touches;//35
    uint8_t touchpad1_position[3];//36-38
    uint8_t touchpad2_touches;//39
    uint8_t touchpad2_position[3];//40-42
    uint8_t unknown3[21];
} hid_ps4_report_t;


void ps4_driver_init(uint8_t busid, uint32_t reg_base);
void ps4_driver_process(void);
void ps4_driver_report(uint8_t busid,hid_ps4_report_t *);


#endif /* SRC_PS4_DRIVER_H_ */
