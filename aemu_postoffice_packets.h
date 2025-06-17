#ifndef __AEMU_POSTOFFICE_PACKETS_H
#define __AEMU_POSTOFFICE_PACKETS_H

#include <stdint.h>

// structs here are gcc little endian

typedef enum{
	AEMU_POSTOFFICE_INIT_PDP,
	AEMU_POSTOFFICE_INIT_PTP_LISTEN,
	AEMU_POSTOFFICE_INIT_PTP_CONNECT,
	AEMU_POSTOFFICE_INIT_PTP_ACCEPT
} aemu_postoffice_init_type;

typedef struct __attribute__((packed)) aemu_postoffice_init{
	int32_t init_type;
	char src_addr[8];
	uint16_t sport;
	char dst_addr[8];
	uint16_t dport;
} aemu_postoffice_init;

typedef struct __attribute__((packed)) aemu_postoffice_pdp{
	char addr[8];
	uint16_t port;
	uint32_t size;
};

#endif
