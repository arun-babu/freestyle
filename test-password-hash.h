#include "freestyle.h"

char *test_salt[64] = {
	"0abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!",
	"1abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@",
	"2abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#",
	"3abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$",
	"4abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789%",
	"5abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789^",
	"6abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789&",
	"7abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789*",
	"8abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789(",
	"9abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789)",

	"0abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~",
	"1abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`",
	"2abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-",
	"3abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+",
	"4abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!",
	"5abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789|",
	"6abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<",
	"7abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789>",
	"8abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,",
	"9abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.",

	"0abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789;",
	"1abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:",
	"2abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789[",
	"3abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789]",
	"4abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{",
	"5abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789}",
	"6abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'",
	"7abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_",
	"8abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=",
	"9abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
};

char *test_password[30] = {
	"123456",
	"12345",
	"password",
	"password1",
	"123456789",
	"12345678",
	"1234567890",
	"abc123",
	"computer",
	"tigger",
	"1234",
	"qwerty",
	"money",
	"carmen",
	"mickey",
	"secret",
	"summer",
	"internet",
	"a1b2c3",
	"123",
	"service",
	"canada",
	"hello",
	"ranger",
	"shadow",
	"baseball",
	"donald",
	"harley",
	"hockey",
	"letmein"
};

u8 test_hash[30][64 + 1 + 7] = {
	{0x66,0x6c,0xb3,0x4c,0xb1,0x74,0xc7,0x43,0x8f,0x44,0x1d,0xf2,0xc8,0xaa,0xe0,0xcf,0x2f,0xbc,0xca,0xdb,0x4e,0x61,0xf2,0xea,0x03,0x5a,0x8d,0x94,0x90,0xd5,0xc8,0x25,0xff,0x83,0xae,0x32,0x89,0x03,0x27,0xd1,0x93,0xec,0x45,0x87,0xbf,0x4b,0x37,0x78,0xcb,0x23,0xb0,0xd5,0xc3,0x6b,0xa0,0xde,0x42,0x92,0xfc,0xb5,0xfc,0x0d,0x12,0x32,0xe7,0x5d,0xb7,0xe8,0xb7,0x96,0x44,0x2f},
	{0x26,0xe1,0xb9,0x1c,0xce,0x7e,0x3f,0xef,0xe4,0x83,0xd2,0x1b,0x49,0xc1,0x33,0x42,0x64,0x19,0x73,0xd6,0x85,0xf4,0x24,0x98,0xc2,0xf4,0xf6,0x32,0xeb,0x7e,0xda,0x95,0xfd,0x32,0x15,0x44,0xe4,0xc6,0x8a,0xf4,0x87,0xcd,0x0f,0x40,0x97,0x8c,0x78,0x4a,0x3b,0x99,0x82,0x9e,0xe2,0x09,0xf4,0x3b,0x04,0x81,0xf7,0xc2,0xb6,0xfb,0x54,0xfa,0xc3,0x99,0x99,0xfa,0xdb,0x28,0x57,0x67},
	{0xaf,0x90,0x9e,0x00,0x2b,0x71,0x3c,0xbb,0xc6,0xcf,0xb5,0xc4,0x6e,0xd2,0x28,0x28,0xfc,0xa0,0x00,0xf2,0x8f,0xfd,0x92,0xf4,0x0d,0x48,0x2b,0x87,0xad,0x3e,0xdf,0xc6,0xdb,0x5e,0x4a,0x75,0x7f,0x28,0x8e,0x5f,0xd8,0x1d,0x9c,0xd8,0x4d,0x3d,0xa0,0xb1,0x9c,0x93,0x77,0x6a,0xb8,0xe6,0x63,0x9c,0x39,0x00,0x66,0x4e,0x35,0xde,0xb2,0xa4,0xb4,0x4f,0x81,0x5c,0xba,0x39,0xad,0x4b},
	{0x37,0x64,0x89,0xf6,0x1c,0x3a,0x56,0x77,0xb6,0x9c,0x5f,0xd6,0x70,0x99,0xa9,0x85,0x48,0x62,0x0f,0xa4,0xf6,0xe5,0xd1,0x72,0x4f,0x91,0x43,0x5f,0x87,0xbe,0xda,0x26,0xdd,0xf0,0x71,0x9b,0x66,0x96,0xa3,0x27,0x31,0x38,0x65,0xac,0x94,0x55,0x4f,0xfe,0xf2,0xdc,0x32,0x43,0xb5,0x39,0xc2,0xac,0xda,0xcc,0xd8,0x59,0x3d,0xb8,0x58,0xa7,0x3b,0xa0,0x6a,0xdd,0x49,0x68,0x40,0x06},
	{0x3a,0xe6,0x5f,0x8a,0x3d,0x4c,0xac,0x9e,0xe1,0x4e,0x0f,0x9d,0x28,0xbb,0xdb,0x27,0xc7,0x28,0x5e,0x37,0x4a,0x25,0x89,0x09,0x87,0xf4,0x84,0xf8,0x2b,0x5d,0xc1,0x36,0x87,0x97,0x05,0xd2,0x4b,0x60,0x25,0x64,0x1a,0x1b,0xe5,0x24,0xeb,0x72,0x93,0x89,0xb2,0x66,0x1d,0x69,0x90,0x55,0xe0,0x2c,0x71,0x31,0xbf,0x80,0x91,0x28,0xda,0xce,0xe0,0x97,0x1c,0x7e,0x6b,0xa1,0xee,0x3b},
	{0x2b,0xa9,0x20,0x56,0xfc,0x4e,0x28,0xa3,0x89,0xd7,0xe4,0x7c,0x87,0x5d,0xbe,0xcd,0x0d,0x67,0x18,0x8d,0xd2,0x9f,0xc4,0xb0,0x1d,0x29,0xe5,0x58,0xd5,0x37,0xca,0x22,0x99,0x28,0x1c,0xe8,0xb1,0xf0,0x2b,0x15,0x31,0xe5,0x76,0xf2,0x67,0x63,0x39,0x41,0x24,0x2f,0xf1,0x26,0x8d,0xa8,0x2f,0xc3,0xb9,0x8e,0x0b,0xc2,0xc5,0x83,0x4b,0x9a,0xcc,0x82,0xd0,0xea,0x38,0x50,0x8a,0x6f},
	{0xd9,0x1c,0xb5,0x83,0xfc,0x17,0x65,0x76,0x21,0x0b,0x6b,0x6a,0x15,0x89,0xdf,0xc8,0xde,0x8b,0x16,0x05,0x45,0xe8,0x2d,0x47,0x57,0x7a,0x06,0x85,0x83,0xb3,0xc4,0x81,0xb7,0x78,0x17,0x9e,0xb8,0xa3,0x3f,0x14,0xa5,0x8e,0x1e,0x35,0x0a,0x47,0x1a,0xd0,0xb8,0x36,0x73,0x5d,0xca,0xb1,0xd5,0x65,0x1b,0x3b,0xa6,0xf1,0x0f,0xfa,0x8f,0xd1,0xc7,0x51,0x5b,0xb8,0x9e,0xb3,0x07,0x8e},
	{0x56,0xf2,0x08,0x6f,0xb5,0xc5,0x51,0xd7,0x08,0x0b,0xe0,0x0c,0x7c,0x1d,0x5c,0x46,0x04,0xf5,0x1c,0x5b,0x16,0xc2,0xde,0x81,0x4a,0xf7,0x8a,0xab,0x4f,0x64,0x3d,0xf2,0xc1,0x03,0x8f,0xe4,0x42,0x10,0x50,0x4f,0x21,0xa4,0x53,0x72,0x92,0xee,0x02,0x6f,0x47,0x99,0xb4,0xdf,0x48,0xc5,0x80,0x74,0x46,0x5d,0x87,0x64,0x93,0xaf,0x61,0x0c,0x79,0x01,0xd4,0xf5,0xd7,0x79,0xe1,0xf0},
	{0x8e,0x94,0x33,0xd7,0x65,0x4b,0x3e,0x98,0xaf,0xad,0x03,0x0b,0x70,0xbb,0x03,0x6f,0x9b,0x34,0x5a,0x5d,0xb2,0x9f,0xf1,0x81,0x00,0x90,0x79,0x28,0x35,0xe6,0x3f,0xd9,0xec,0xd8,0x1c,0xf7,0xb1,0x5f,0xca,0x3c,0x9c,0xf5,0x08,0xb6,0xb9,0x18,0x5f,0xf9,0xb8,0x14,0x02,0xc2,0x56,0x6e,0xc5,0xbd,0x4e,0x03,0xe6,0x75,0x49,0x0a,0xf3,0xdd,0x05,0x32,0x53,0x3f,0x09,0x02,0x7a,0xb8},
	{0x3a,0xca,0x65,0xb0,0xcb,0x9a,0xa3,0x5e,0x5b,0xcd,0x0d,0x0e,0x36,0x54,0x0b,0xa3,0x60,0xde,0xac,0xe2,0x3c,0x55,0xdd,0x2e,0x8a,0xcd,0xc7,0x89,0xdc,0xd1,0x91,0x24,0xa1,0xad,0x1f,0x7d,0xd9,0x72,0xe4,0x0a,0xc3,0x5a,0x30,0x8c,0xe9,0x0b,0x53,0x1f,0x5b,0x8b,0xcc,0x59,0xe4,0xb2,0x0a,0x1a,0x61,0xc9,0x5a,0x42,0xdf,0xb7,0x4f,0x66,0xbb,0x50,0x80,0x31,0x3b,0xfe,0x35,0x10},
	{0x72,0x28,0xc9,0xbd,0xf0,0x4d,0xee,0xe1,0xf3,0xc4,0x99,0x4a,0x09,0x99,0xf7,0x9e,0x73,0x47,0xb8,0x4b,0x4a,0xef,0xca,0x86,0x6e,0x3a,0xd7,0x76,0x6b,0xde,0x7c,0xda,0x5d,0x08,0xb7,0x70,0x69,0xc3,0x00,0xa6,0xa2,0x84,0x9f,0x99,0x19,0xee,0x93,0xe5,0xc4,0x58,0x7e,0x8e,0x7e,0x42,0xc8,0x4e,0x71,0x29,0x46,0x2c,0x27,0xb3,0xed,0xbf,0xa3,0x0f,0x65,0x16,0x5b,0x60,0x18,0xdb},
	{0xb3,0x92,0x64,0xca,0x44,0x4d,0x69,0xc1,0x17,0xf6,0x28,0x4e,0x17,0x9e,0xff,0x1d,0xac,0x19,0x65,0x28,0x5a,0x32,0xfd,0x5a,0x90,0xa9,0xc3,0xfd,0xe5,0xd6,0x08,0x61,0x28,0x62,0x09,0x88,0x1b,0x9a,0xe5,0xb2,0x9a,0xf1,0x8c,0x24,0xce,0x48,0xe9,0xf2,0x25,0x6a,0xb2,0x6f,0x7b,0x19,0x17,0x32,0x99,0x9b,0x34,0x6b,0x6c,0xa9,0x22,0xc2,0xe8,0x14,0xa8,0xc3,0x2d,0xa5,0xce,0x82},
	{0x2c,0xed,0x93,0xab,0xbc,0xb4,0x4f,0x8e,0x76,0xd0,0x66,0x97,0xcb,0x62,0x6a,0x6c,0xa8,0x35,0x6b,0x83,0x3b,0x33,0x3d,0x31,0xe2,0xda,0x1d,0x52,0xf3,0xa2,0x69,0x5f,0xd4,0xca,0x30,0x77,0x00,0x8b,0xfd,0x2d,0x7d,0x29,0x40,0x3a,0x3b,0x65,0x7b,0xa3,0xf9,0xdc,0x18,0xc2,0xe3,0x97,0x63,0xf7,0x6a,0xd5,0xa9,0xdd,0xea,0x37,0x93,0xcd,0x5b,0xe4,0x68,0x10,0xfc,0x87,0xca,0xcc},
	{0xee,0x8a,0x04,0x72,0xfc,0x07,0x37,0xc8,0xcb,0x80,0xd7,0x67,0x94,0xfc,0xe1,0xf7,0xd1,0x19,0x42,0xca,0xbb,0x48,0x6e,0x35,0x54,0x4b,0x6a,0xd2,0x0b,0x5c,0x8a,0xba,0xc9,0x88,0x7c,0x4f,0x91,0xff,0xfd,0xf2,0x77,0x9f,0xda,0xfe,0x8a,0xbb,0xc9,0xe3,0xad,0xf6,0xde,0x76,0x90,0xc2,0x49,0x4b,0x8c,0x67,0xa7,0x77,0x19,0xf6,0x61,0x88,0xab,0x2f,0xb0,0x3b,0x73,0x5c,0xd9,0x46},
	{0x8d,0xb0,0x12,0x2e,0x61,0x46,0xbc,0xc9,0x5c,0xa7,0x07,0x58,0xd1,0x7f,0x63,0xd3,0x3f,0xac,0x59,0x17,0xdc,0x34,0xe1,0x42,0xad,0x42,0x24,0xcb,0xa9,0x8e,0xf8,0xdd,0x8e,0xdf,0xda,0x89,0xd9,0xb4,0x49,0x1e,0xdd,0xce,0x03,0x09,0x8b,0x85,0x14,0x2c,0x3c,0x06,0xf5,0x48,0x76,0x7e,0x92,0x8c,0x80,0x56,0x62,0x23,0x7e,0x3a,0x8f,0xaf,0x17,0x14,0x0e,0x9a,0x1b,0x10,0x93,0x1a},
	{0x2b,0xff,0xe1,0x74,0xa5,0x5a,0xc0,0x9b,0xd0,0x7a,0xd3,0xaa,0x18,0xd7,0xf8,0xd3,0x7f,0x95,0xa2,0x7f,0x97,0xc7,0xad,0x02,0x7a,0x5a,0xe4,0x65,0x0e,0xc4,0xe6,0xca,0x5f,0xea,0xe5,0xfe,0x99,0x03,0x5d,0xf1,0x5f,0x75,0x93,0x42,0x68,0x65,0x21,0xef,0x23,0x3c,0x15,0xfb,0xb2,0x2c,0xc2,0xa9,0x44,0x2c,0xdc,0x76,0x28,0xdb,0x6d,0xfd,0x4b,0x6a,0x90,0xf6,0x25,0xff,0x8f,0xd1},
	{0xf8,0xaa,0x96,0xce,0xee,0x58,0x7c,0xea,0x7e,0x1b,0x06,0xab,0x2d,0x7c,0x48,0xcd,0x39,0xb3,0xc9,0x71,0x32,0x57,0x15,0xf2,0x34,0x8d,0x1b,0xfa,0xb0,0xed,0x12,0xed,0x30,0x46,0x38,0x58,0x9c,0x5a,0x68,0x6f,0x13,0xc9,0x28,0xe4,0x0c,0xf3,0x32,0x60,0x16,0x39,0xa2,0x9c,0x23,0x8b,0xc0,0xcb,0x98,0x04,0x78,0xcf,0x4e,0x7c,0xe4,0xf4,0x95,0xcc,0xc8,0x66,0x41,0xc1,0x74,0x3c},
	{0x88,0xbe,0xb6,0xb0,0xb0,0xe7,0x27,0x17,0xb2,0x3e,0x80,0x9f,0x69,0x11,0xf9,0xc6,0x2b,0x0f,0x71,0x9b,0xf1,0xf9,0xcd,0xd2,0x53,0x65,0x4c,0xb9,0x74,0x89,0xc2,0x60,0x2c,0xb6,0x93,0x58,0x35,0x91,0xb3,0xd4,0x6c,0x24,0x66,0x8a,0xf7,0x64,0x71,0x13,0x19,0xa2,0xb3,0xe0,0xc2,0xd7,0x28,0x09,0xd1,0x47,0x4a,0xd0,0x83,0x2e,0x76,0x1b,0x84,0x2a,0x87,0x59,0xef,0xb5,0xdb,0x65},
	{0x68,0xd6,0x89,0x50,0xb7,0x99,0x69,0x4e,0x35,0xcf,0x3b,0xb6,0x1d,0x93,0x0c,0x37,0xce,0xdf,0x4f,0x41,0xf5,0x5a,0x14,0xc9,0x87,0x6c,0x3f,0x58,0xfb,0x45,0xb3,0x8e,0x5d,0xf3,0x81,0x0a,0x17,0xb1,0xf7,0x46,0x44,0xfa,0x51,0x86,0xd7,0x8c,0x01,0x7e,0x47,0x19,0xb8,0x6f,0xad,0xbd,0x0b,0x23,0xd1,0x76,0x53,0xc9,0x39,0x88,0x78,0x1c,0x91,0xcd,0x4d,0x9a,0x94,0x14,0x12,0x7b},
	{0x92,0x47,0xd7,0xa1,0x12,0xcd,0x10,0xa2,0xa2,0xcc,0xf9,0xdb,0x98,0x27,0x40,0x68,0xe6,0x5d,0x65,0x4d,0xc2,0x5e,0xcf,0x8d,0x34,0x08,0x68,0x31,0x72,0xe5,0x67,0xf1,0xc1,0xc1,0xb0,0xf6,0x5a,0x07,0xa7,0x5c,0xce,0xb2,0x3b,0xe1,0xc5,0x6a,0xcd,0x79,0xca,0x3f,0x30,0x63,0x45,0x4f,0x15,0x19,0x99,0xa3,0x01,0xd1,0x95,0x18,0xde,0xd8,0x32,0xe8,0xf2,0xd3,0xc1,0xfa,0x7e,0xcc},
	{0x00,0x38,0x74,0xf4,0xd0,0xa8,0x40,0x73,0xfd,0x6d,0xf9,0x47,0x4c,0x7e,0xde,0x13,0x39,0xa0,0x80,0xf4,0xbb,0x94,0xb0,0xa8,0x99,0xe4,0x2d,0x69,0x3a,0x76,0x3d,0x37,0x21,0xb5,0x71,0x8d,0xf7,0x53,0xc8,0x01,0xc4,0xf1,0x56,0x4b,0xe4,0xdf,0x63,0x2a,0x71,0xe5,0x14,0xb8,0x73,0x4d,0x72,0xd9,0x0e,0x33,0x45,0x51,0x74,0xc6,0x7d,0x2f,0xfc,0x09,0x00,0xc5,0xca,0x8b,0x9a,0x3d},
	{0xa7,0xe9,0xa6,0xdd,0xd8,0xd1,0xce,0x53,0x72,0x20,0xb3,0xbc,0x3d,0x9e,0xa7,0xd2,0xdb,0x14,0x9d,0xb3,0x1b,0x73,0x1f,0x01,0x6f,0xdf,0x65,0x66,0x9a,0xfe,0x4a,0xf7,0xc1,0xbb,0xc9,0xe2,0x67,0xc9,0x36,0x7d,0x24,0xc2,0xac,0x1c,0x51,0x8b,0x71,0x40,0x1d,0x6f,0x35,0x7a,0x06,0xf7,0xa2,0xbe,0x28,0x03,0x57,0x46,0x60,0x8f,0x99,0x8c,0x5f,0x7d,0x81,0x39,0xfd,0xf7,0x53,0xc6},
	{0x4d,0x4e,0x25,0xf3,0x1f,0x84,0x7b,0x47,0x3f,0x60,0x63,0x10,0x6d,0x53,0x8e,0x42,0x99,0x62,0x4a,0x0a,0x2e,0x8b,0xcf,0xfc,0x10,0x33,0x66,0x87,0x12,0x7f,0x33,0xae,0x9f,0x12,0x74,0x42,0x41,0x30,0x64,0x2e,0xb9,0x23,0x72,0xbf,0xbb,0xde,0x32,0xc2,0x42,0x4e,0xe5,0x21,0x64,0x0e,0xf5,0x7a,0x05,0xd4,0xa6,0x67,0xbe,0x21,0x98,0x0d,0x36,0x9d,0x73,0xc7,0xf5,0xf0,0xba,0xea},
	{0x1b,0x90,0xba,0x2f,0xbe,0xbd,0xf3,0xad,0x6e,0xe3,0x9e,0x70,0x53,0xe6,0xe7,0xa0,0x3a,0x02,0x70,0xfe,0xc2,0x9e,0xf4,0xb0,0x1d,0x81,0xbc,0x67,0x7a,0x3e,0x46,0xc2,0x2a,0x61,0x95,0xda,0x52,0x3a,0xc6,0xbb,0x4e,0x8d,0x32,0x03,0x9e,0xf4,0xee,0xfb,0x81,0x1f,0x76,0x14,0x17,0xf2,0x76,0xfe,0x97,0x35,0xf4,0xf4,0x76,0x03,0x82,0xc5,0x17,0x64,0xda,0xeb,0x99,0xf8,0x1d,0xf4},
	{0x28,0xb5,0xd1,0x3e,0x5a,0xb1,0x49,0xd4,0x19,0x83,0x3a,0x3a,0x6f,0xdb,0xb9,0xcf,0xcf,0x67,0x7a,0xa8,0x04,0x65,0x79,0x8d,0x6c,0xea,0x83,0xd4,0x82,0x33,0xa2,0xc9,0xd5,0x8f,0x2d,0xf6,0xfd,0x7b,0xb8,0x87,0x47,0x4e,0x1a,0x1c,0xb9,0xc2,0xa3,0xa6,0xc5,0xb7,0x56,0x7e,0x1b,0xf2,0xd8,0xbf,0x64,0x6b,0x48,0x74,0x67,0x94,0xb7,0x27,0xcc,0x7a,0x54,0xae,0x55,0x61,0xd5,0xe0},
	{0xbb,0x72,0x9f,0xef,0x37,0xff,0x6b,0x31,0xef,0xad,0x6a,0xfe,0x9c,0xf2,0x9d,0x34,0xbd,0xfa,0xe3,0xa5,0x9c,0xd5,0x07,0x4b,0xfa,0xa1,0xc5,0x3f,0x15,0x76,0x67,0x27,0x29,0xa8,0x90,0x23,0x25,0x00,0x6f,0xc1,0x02,0xc3,0xa9,0x5e,0xd9,0xa8,0x09,0x0b,0x8e,0x5a,0xcf,0x50,0x38,0xa6,0x35,0x73,0x16,0x08,0x52,0x66,0x99,0x21,0x8e,0xa1,0xcf,0x6e,0x2a,0x3e,0x1d,0xa7,0xb7,0x11},
	{0x37,0x24,0x14,0xb7,0x98,0x7f,0x7a,0xbe,0x24,0x09,0xbb,0x55,0x09,0x54,0xd2,0x8c,0x24,0x0b,0xe8,0xfc,0x6b,0x06,0x7f,0x22,0x29,0x0c,0x00,0xef,0x49,0x9e,0xc6,0x80,0xe8,0x72,0xaf,0xa8,0xfa,0xff,0x31,0x63,0x4b,0xf5,0x3d,0x51,0x3c,0x54,0xd7,0x3f,0x99,0x9f,0x61,0xf1,0x17,0x8e,0xa8,0xa6,0xf4,0x54,0x96,0x91,0x7f,0x52,0x05,0xfd,0x31,0xea,0xf3,0x44,0x3f,0x0f,0x8b,0x98},
	{0x15,0x33,0x26,0x80,0xb1,0x4f,0x9c,0xbf,0x1d,0x30,0x08,0x85,0xd2,0x3d,0x2e,0xf9,0xf6,0x2c,0x67,0xf3,0x03,0x6b,0x71,0xae,0x3e,0x91,0x5f,0x23,0x99,0xd7,0x70,0x2e,0xf4,0x7a,0x34,0xa3,0x52,0x9b,0x1b,0xa4,0x64,0xe4,0x62,0x2e,0x50,0x51,0x2a,0xc5,0x37,0x90,0xd3,0xa3,0x9a,0xe2,0xe6,0xe8,0x66,0x05,0x45,0x80,0x87,0xc2,0x0f,0xf8,0x7f,0x2b,0x2c,0xf1,0xa8,0xe4,0x04,0xdc},
	{0x00,0x8f,0x81,0x49,0x88,0xfb,0xf7,0xef,0xb8,0x6e,0xf4,0x56,0x5c,0xfc,0xd2,0x6b,0x09,0xa0,0x0b,0xdd,0xca,0x8e,0xbb,0x75,0x30,0xf4,0x55,0x17,0x96,0xda,0x13,0xdf,0x13,0xeb,0x0b,0x7c,0xe1,0xa4,0xf4,0xf3,0xad,0x37,0x4d,0xde,0xbd,0xc7,0x3f,0xac,0xc3,0x4f,0xca,0x18,0x3e,0x11,0x34,0x84,0x44,0xe2,0xc1,0xc1,0xd3,0xda,0x39,0x64,0x49,0x69,0xf6,0x43,0xa3,0xa8,0xbb,0x20},
	{0xdd,0xe0,0xe6,0x95,0xbf,0x9a,0xf2,0xe5,0xca,0xa3,0x74,0xf2,0x3c,0x1b,0x49,0x72,0xa7,0x66,0x02,0x8f,0xf9,0xec,0x94,0x80,0x26,0x8d,0x78,0x42,0x11,0x13,0x13,0x3c,0xa9,0x79,0x27,0xb5,0x39,0x75,0xf7,0x0d,0x2a,0x98,0x63,0x9e,0xe7,0x8f,0x21,0xc7,0x6d,0x66,0x99,0x82,0xb7,0x4b,0xec,0x36,0x73,0x68,0x34,0xe0,0x8e,0x2f,0x0d,0xf4,0x45,0x9e,0xd4,0x8c,0xc3,0x3f,0xb8,0x95},
};
