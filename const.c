
#define C240 0x1BD11BDAA9FC1A22ULL

// rotation constants for Threefish-256
static const u8 rot_256[8][2] = {
	{14, 16},
	{52, 57},
	{23, 40},
	{ 5, 37},
	{25, 33},
	{46, 12},
	{58, 22},
	{32, 32},
};

// rotation constants for Threefish-512
static const u8 rot_512[8][4] = {
	{46, 36, 19, 37},
	{33, 27, 14, 42},
	{17, 49, 36, 39},
	{44,  9, 54, 56},
	{39, 30, 34, 24},
	{13, 50, 10, 17},
	{25, 29, 39, 43},
	{ 8, 35, 56, 22},
};

// rotation constants for Threefish-1024
static const u8 rot_1024[8][8] = {
	{24, 13,  8, 47,  8, 17, 22, 37},
	{38, 19, 10, 55, 49, 18, 23, 52},
	{33,  4, 51, 13, 34, 41, 59, 17},
	{ 5, 20, 48, 41, 47, 28, 16, 25},
	{41,  9, 37, 31, 12, 47, 44, 30},
	{16, 34, 56, 51,  4, 53, 42, 41},
	{31, 44, 47, 46, 19, 42, 44, 25},
	{ 9, 48, 35, 52, 23, 31, 37, 20},
};

// permutation constants
static const u8 perm_256[4][4] = {
	{0, 1, 2, 3},
	{0, 3, 2, 1},
	{0, 1, 2, 3},
	{0, 3, 2, 1},
};

// ghci> take 4 $ iterate (map ([2,1,4,7,6,5,0,3] !!)) [0..7]
static const u8 perm_512[4][8] = {
	{0, 1, 2, 3, 4, 5, 6, 7},
	{2, 1, 4, 7, 6, 5, 0, 3},
	{4, 1, 6, 3, 0, 5, 2, 7},
	{6, 1, 0, 7, 2, 5, 4, 3},
};

static const u8 perm_1024[4][16] = {
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1},
	{0, 7, 2, 5, 4, 3, 6, 1, 12, 15, 14, 13, 8, 11, 10, 9},
	{0, 15, 2, 11, 6, 13, 4, 9, 14, 1, 8, 5, 10, 3, 12, 7},
};

