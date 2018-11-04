#ifndef JHD_ERROR_H_
#define JHD_ERROR_H_

#define JHD_HTTP2_NO_ERROR                     0x0
#define JHD_HTTP2_PROTOCOL_ERROR               0x10000000
#define JHD_HTTP2_INTERNAL_ERROR               0x20000000
#define JHD_HTTP2_FLOW_CTRL_ERROR              0x30000000
#define JHD_HTTP2_SETTINGS_TIMEOUT             0x40000000
#define JHD_HTTP2_STREAM_CLOSED                0x50000000
#define JHD_HTTP2_SIZE_ERROR                   0x60000000
#define JHD_HTTP2_REFUSED_STREAM               0x70000000
#define JHD_HTTP2_CANCEL                       0x80000000
#define JHD_HTTP2_COMP_ERROR                   0x90000000
#define JHD_HTTP2_CONNECT_ERROR                0xa0000000
#define JHD_HTTP2_ENHANCE_YOUR_CALM            0xb0000000
#define JHD_HTTP2_INADEQUATE_SECURITY          0xc0000000
#define JHD_HTTP2_HTTP_1_1_REQUIRED            0xd0000000
#define JHD_HTTP2_UNSUPPORTED_TYPE             0xf0000000




#define JHD_HTTP2_ERROR_HUFF_DECOE             0xF0000009

#define JHD_HTTP2_REFUSED_STREAM_MAX_STREAM    0x70100000



#endif /* JHD_ERROR_H_ */
