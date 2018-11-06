#ifndef JHD_ERROR_H_
#define JHD_ERROR_H_

#define JHD_HTTP2_NO_ERROR                     						0x0




/******************************************/

#define JHD_HTTP2_PROTOCOL_ERROR              						0x01000000

#define JHD_HTTP2_PROTOCOL_ERROR_INVALID_FRAME_TYPE               	0x01100000
#define JHD_HTTP2_PROTOCOL_ERROR_INVALID_STREAM_ID               	0x01200000

#define JHD_HTTP2_PROTOCOL_ERROR_INVALID_DATA_PAYLOAD               0x01300000

/******************************************/
#define JHD_HTTP2_INTERNAL_ERROR               						0x02000000

#define JHD_HTTP2_INTERNAL_ERROR_READ_IO               				0x02100000
/******************************************/
#define JHD_HTTP2_FLOW_CTRL_ERROR              0x03000000

#define JHD_HTTP2_FLOW_CTRL_ERROR_CONNECTION              0x03100000
#define JHD_HTTP2_FLOW_CTRL_ERROR_STREAM              0x03200000

/******************************************/
#define JHD_HTTP2_SETTINGS_TIMEOUT             0x04000000
/******************************************/
#define JHD_HTTP2_STREAM_CLOSED                0X05000000
/******************************************/
#define JHD_HTTP2_SIZE_ERROR                   0x06000000

#define JHD_HTTP2_FRAME_MAX_SIZE_ERROR         0x06100000



/******************************************/

#define JHD_HTTP2_REFUSED_STREAM               0x07000000
/******************************************/
#define JHD_HTTP2_CANCEL                       0x08000000
/******************************************/
#define JHD_HTTP2_COMP_ERROR                   0x09000000
/******************************************/
#define JHD_HTTP2_CONNECT_ERROR                0x0a000000
/******************************************/
#define JHD_HTTP2_ENHANCE_YOUR_CALM            0x0b000000


#define JHD_HTTP2_ENHANCE_YOUR_CALM_READ_FRAME_HEADER            0x0b100000


/******************************************/

#define JHD_HTTP2_INADEQUATE_SECURITY          0x0c000000
/******************************************/
#define JHD_HTTP2_HTTP_1_1_REQUIRED            0x0d000000

/******************************************/
#define JHD_HTTP2_UNSUPPORTED_TYPE             0x0f000000




#define JHD_HTTP2_ERROR_HUFF_DECOE             0xF0000009

#define JHD_HTTP2_REFUSED_STREAM_MAX_STREAM    0x70100000



#endif /* JHD_ERROR_H_ */
