/*
 * crc32.h
 *
 *  Created on: 2024��7��5��
 *      Author: user
 */

#ifndef SRC_CRC32_H_
#define SRC_CRC32_H_
#include <stdint.h>
uint32_t crc32_le(uint32_t crc, uint8_t const * buf,uint32_t len);

#endif /* SRC_CRC32_H_ */
