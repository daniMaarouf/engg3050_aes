#ifndef SRC_MODES_H_
#define SRC_MODES_H_

#include "basic_aes.h"

//#define AES_N 65536
#define AES_N 8192
#define AES_W 64

#pragma SDS data access_pattern(in1:SEQUENTIAL, out1:SEQUENTIAL, in2:SEQUENTIAL, out2:SEQUENTIAL, in3:SEQUENTIAL, out3:SEQUENTIAL, in4:SEQUENTIAL, out4:SEQUENTIAL)
#pragma SDS data mem_attribute(in1:PHYSICAL_CONTIGUOUS, out1:PHYSICAL_CONTIGUOUS, in2:PHYSICAL_CONTIGUOUS, out2:PHYSICAL_CONTIGUOUS, in3:PHYSICAL_CONTIGUOUS, out3:PHYSICAL_CONTIGUOUS, in4:PHYSICAL_CONTIGUOUS, out4:PHYSICAL_CONTIGUOUS)
#pragma SDS data mem_attribute(in1:NON_CACHEABLE, out1:NON_CACHEABLE, in2:NON_CACHEABLE, out2:NON_CACHEABLE, in3:NON_CACHEABLE, out3:NON_CACHEABLE, in4:NON_CACHEABLE, out4:NON_CACHEABLE)
#pragma SDS data sys_port(in1: AFI, out1:AFI, in2: AFI, out2:AFI, in3: AFI, out3:AFI, in4: AFI, out4:AFI)
void aes_ecb_256(const ap_uint<AES_W> in1[AES_N], const ap_uint<AES_W> in2[AES_N], const ap_uint<AES_W> in3[AES_N], const ap_uint<AES_W> in4[AES_N],
		ap_uint<AES_W> out1[AES_N], ap_uint<AES_W> out2[AES_N], ap_uint<AES_W> out3[AES_N], ap_uint<AES_W> out4[AES_N], const ap_uint<256> key);

#pragma SDS data access_pattern(in:SEQUENTIAL, out:SEQUENTIAL)
#pragma SDS data mem_attribute(in:PHYSICAL_CONTIGUOUS, out:PHYSICAL_CONTIGUOUS)
#pragma SDS data sys_port(in: ACP, out:ACP)
void aes_ctr_256(const ap_uint<AES_W> in[AES_N], ap_uint<AES_W> out[AES_N], const ap_uint<256> key, ap_uint<128> & ctr_init);

#pragma SDS data access_pattern(in1:SEQUENTIAL, out1:SEQUENTIAL, in2:SEQUENTIAL, out2:SEQUENTIAL, in3:SEQUENTIAL, out3:SEQUENTIAL, in4:SEQUENTIAL, out4:SEQUENTIAL)
#pragma SDS data mem_attribute(in1:NON_CACHEABLE|PHYSICAL_CONTIGUOUS, out1:NON_CACHEABLE|PHYSICAL_CONTIGUOUS, in2:NON_CACHEABLE|PHYSICAL_CONTIGUOUS, out2:NON_CACHEABLE|PHYSICAL_CONTIGUOUS, in3:NON_CACHEABLE|PHYSICAL_CONTIGUOUS, out3:NON_CACHEABLE|PHYSICAL_CONTIGUOUS, in4:NON_CACHEABLE|PHYSICAL_CONTIGUOUS, out4:NON_CACHEABLE|PHYSICAL_CONTIGUOUS)
#pragma SDS data sys_port(in1: AFI, out1:AFI, in2: AFI, out2:AFI, in3: AFI, out3:AFI, in4: AFI, out4:AFI)
void aes_ctr_256_hp(const ap_uint<AES_W> in1[AES_N], const ap_uint<AES_W> in2[AES_N], const ap_uint<AES_W> in3[AES_N], const ap_uint<AES_W> in4[AES_N],
		ap_uint<AES_W> out1[AES_N], ap_uint<AES_W> out2[AES_N], ap_uint<AES_W> out3[AES_N], ap_uint<AES_W> out4[AES_N], const ap_uint<256> key, ap_uint<128> & ctr_init);

#pragma SDS data access_pattern(in:SEQUENTIAL, out:SEQUENTIAL)
#pragma SDS data mem_attribute(in:PHYSICAL_CONTIGUOUS, out:PHYSICAL_CONTIGUOUS)
#pragma SDS data sys_port(in: ACP, out:ACP)
void aes_ofb_256(const ap_uint<AES_W> in[AES_N], ap_uint<AES_W> out[AES_N], const ap_uint<256> key, ap_uint<128> & iv);

#endif /* SRC_MODES_H_ */
