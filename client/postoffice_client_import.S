	.set noreorder

#include "pspstub.s"

	STUB_START "aemu_postoffice_client",0x00090011,0x00170005
	STUB_FUNC  0x1,pdp_create_v4
	STUB_FUNC  0x2,pdp_delete
	STUB_FUNC  0x3,pdp_send
	STUB_FUNC  0x4,pdp_recv
	STUB_FUNC  0x6,pdp_peek_next_size
	STUB_FUNC  0x7,pdp_buffered_data_size
	STUB_FUNC  0x8,pdp_send_buf_not_full
	STUB_FUNC  0x9,pdp_is_dead

	STUB_FUNC  0x101,ptp_listen_v4
	STUB_FUNC  0x102,ptp_accept
	STUB_FUNC  0x103,ptp_connect_v4
	STUB_FUNC  0x104,ptp_send
	STUB_FUNC  0x105,ptp_recv
	STUB_FUNC  0x106,ptp_close
	STUB_FUNC  0x107,ptp_listen_close
	STUB_FUNC  0x10A,ptp_peek_next_size
	STUB_FUNC  0x10B,ptp_send_buf_not_full
	STUB_FUNC  0x10C,ptp_listen_has_request
	STUB_FUNC  0x10D,ptp_is_dead
	STUB_FUNC  0x10E,ptp_listen_is_dead
	STUB_END

	STUB_START "adhocctl",0x00090011,0x00170005
	STUB_FUNC 0x1,create_adhocctl_v1_session_v4
	STUB_FUNC 0x2,destroy_adhocctl_session
	STUB_FUNC 0x3,adhocctl_get_event
	STUB_FUNC 0x4,adhocctl_ping
	STUB_FUNC 0x5,adhocctl_connect
	STUB_FUNC 0x6,adhocctl_disconnect
	STUB_FUNC 0x7,adhocctl_scan
	STUB_FUNC 0x8,adhocctl_chat
	STUB_END
