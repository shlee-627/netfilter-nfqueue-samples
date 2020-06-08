#define NVME_OPC_WRITE      0x01
#define NVME_OPC_READ       0x02
#define NVME_OPC_KEEP_ALIVE 0x18

enum PDU_TYPE {
	ICReq = 0,
	ICResp,
	H2CTermReq,
	C2HTermReq,
	CapsuleCmd,
	CapsuleResp,
	H2CData,
	C2HData,
	R2T
};

struct nvme_pdu_hdr {
	u_char pdu_type;
	u_char flags;
	u_char hlen;				// originally it is 1B
	u_char pdo;				// resv
	int plen;
};

struct nvme_cmd_dword_0 {
	u_char cmd_opc;	// Command Opcode
	u_char fuseop : 2;
	u_char rsvd : 4;				// Reserved
	u_char psdt : 2;		// SGL or PRP
	
	u_short cid;	// 16 bits
};

// Five Section will be used when special FLAGs are enabled.
struct nvme_cmd_dword_10 {
	u_short qid;
	u_short qsize;
};

struct nvme_cmd_dword_11 {
	u_short pc : 1;
	u_short ien : 1;		// Queue Priority (QPRIO)
	u_short rsvd : 14;		// Reserved
	u_short int_vec;		// Completion Queue Identifier (CQID)
};

struct nvme_cmd_dword_12 {
	u_short nvmsetId;		// NVM Set Identifier (NVMSETID)
	u_short rsvd;			// Reserved
};

// Section 9. Directive Receive command
struct nvme_cmd_dword_13 {
};
struct nvme_cmd_dword_14 {
};
struct nvme_cmd_dword_15 {
};


struct _nvme_sgl_data_block_desc {
	u_long address;
	u_int length;
	u_short resv : 3;

	// 1B sgl identifier
	u_char sgl_desc_subtype : 4;
	u_char sgl_desc_type : 4;
};

struct _nvme_sgl_bit_bucket_desc {
	u_long resv;
	u_int length;
	u_short resvi : 3;

	// 1B sgl identifier
	u_char sgl_desc_subtype : 4;
	u_char sgl_desc_type : 4;
};

struct _nvme_sgl_segment_desc {
	u_long address;
	u_int length;
	u_short resv : 3;

	// 1B sgl identifier
	u_char sgl_desc_subtype : 4;
	u_char sgl_desc_type : 4;
};

struct _nvme_sgl_last_segment_desc {
	u_long address;
	u_int length;
	u_short resv : 3;

	// 1B sgl identifier
	u_char sgl_desc_subtype : 4;
	u_char sgl_desc_type : 4;
};

struct _nvme_keyed_sgl_data_block_desc {
	u_long address;
	u_long length : 3;
	u_long key : 4;

	// 1B sgl identifier
	u_char sgl_desc_subtype : 4;
	u_char sgl_desc_type : 4;
};

struct _nvme_transport_sgl_data_block_desc {
	u_long resv;
	u_int length;
	u_short resv2 : 3;
	// 1B sgl identifier
	u_char sgl_desc_subtype : 4;
	u_char sgl_desc_type : 4;
};

// SGL descriptor (16B)
struct nvme_sgl_desc_general {
	// 15B opc type specific
	u_long address; // (8B)
	u_int  length; // (4B)
	u_int  resv; // (3B)

	// 1B sgl identifier
	u_char sgl_desc_subtype : 4;
	u_char sgl_desc_type : 4;
};

// SQE (64B)
struct nvme_cmd {
	struct nvme_cmd_dword_0 cmd_dword0;				// NVMe Command Dword 0

	// Command Dward End
	u_int nsid;										// Namespace ID
	u_long rsvdx2;									// Reserved
	u_long mptr;									// Metadata Pointer

	struct nvme_sgl_desc_general sgl_desc0;		// Data Pointer (DPTR)
	struct nvme_sgl_desc_general sgl_desc1;		// Data Pointer (DPTR)
	struct nvme_sgl_desc_general sgl_desc2;		// Data Pointer (DPTR)
	struct nvme_sgl_desc_general sgl_desc3;		// Data Pointer (DPTR)

	struct nvme_cmd_dword_10 cmd_dword10;			// NVMe Command Dword 10
	struct nvme_cmd_dword_11 cmd_dword11;			// NVMe Command Dword 11
	struct nvme_cmd_dword_12 cmd_dword12;			// NVMe Command Dword 12
	struct nvme_cmd_dword_13 cmd_dword13;			// NVMe Command Dword 13
	struct nvme_cmd_dword_14 cmd_dword14;			// NVMe Command Dword 14
	struct nvme_cmd_dword_15 cmd_dword15;			// NVMe Command Dword 15

	// What's DSM flags?
	char dsm_flag;									// DSM Flags
	// There're several more fields....
};

struct nvme_rw_cmd {
	struct nvme_pdu_hdr pduh;

	struct nvme_cmd cmd;

	u_int hdgst;

	// ... PAD, DATA, DDGST ...
};

struct nvme_c2h_data {
	struct nvme_pdu_hdr pduh;
	
	// PSH
	u_short cccid;			// Command Capsule CID
	u_short rsvd;			// Reserved
	u_int   d_off;			// Data Offset (DATAO)
	u_int   d_len;			// Data Length (DATAL)
	u_int   rsvd2;			// Reserved

	u_int   hdgst;			// HDGST
#define PDA (h)       	0x40 - (h)->pduh.hlen

	// struct nvme_pdu_data data;
	// DATA...
	int     ddgst;			// DDGST
};

struct nvme_cqe{
	// dw0 (4B)
	u_int cmd_spec;

	// dw1 (4B)
	u_int resv;

	// dw2 (4B)
	u_short sqhd;			// SQ Head Pointer
	u_short sqid;			// SQ Identifier

	// dw3 (4B)
	u_short cid;
	u_short phase_tag : 1;
	u_short sf : 15;		// Status Field
};

struct nvme_rw_resp {
	struct nvme_pdu_hdr pduh;
	struct nvme_cqe rccqe;			// NVMe-oF Response Capsule CQE

	u_int   hdgst;			// HDGST
};


