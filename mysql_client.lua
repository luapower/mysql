
--MySQL client protocol in Lua.
--Written by Cosmin Apreutesei. Public domain.
--Original code by Yichun Zhang (agentzh). BSD license.

local ffi = require'ffi'
local bit = require'bit'
local sha1 = require'sha1'.sha1
local glue = require'glue'
local errors = require'errors'

local sub = string.sub
local strbyte = string.byte
local strchar = string.char
local format = string.format
local strrep = string.rep
local band = bit.band
local bxor = bit.bxor
local bor = bit.bor
local shl = bit.lshift
local shr = bit.rshift
local tohex = bit.tohex
local concat = table.concat

local buffer = glue.buffer
local dynarray = glue.dynarray
local index = glue.index
local repl = glue.repl
local update = glue.update

local check_io, check, protect = errors.tcp_protocol_errors'mysql'

local mysql = {}

local COM_QUIT         = 0x01
local COM_QUERY        = 0x03
local COM_STMT_PREPARE = 0x16
local COM_STMT_EXECUTE = 0x17
local COM_STMT_CLOSE   = 0x19

local CLIENT_SSL = 0x0800

local SERVER_MORE_RESULTS_EXISTS = 8

local collation_names = {
	[  1] = 'big5_chinese_ci',
	[  2] = 'latin2_czech_cs',
	[  3] = 'dec8_swedish_ci',
	[  4] = 'cp850_general_ci',
	[  5] = 'latin1_german1_ci',
	[  6] = 'hp8_english_ci',
	[  7] = 'koi8r_general_ci',
	[  8] = 'latin1_swedish_ci',
	[  9] = 'latin2_general_ci',
	[ 10] = 'swe7_swedish_ci',
	[ 11] = 'ascii_general_ci',
	[ 12] = 'ujis_japanese_ci',
	[ 13] = 'sjis_japanese_ci',
	[ 14] = 'cp1251_bulgarian_ci',
	[ 15] = 'latin1_danish_ci',
	[ 16] = 'hebrew_general_ci',
	[ 18] = 'tis620_thai_ci',
	[ 19] = 'euckr_korean_ci',
	[ 20] = 'latin7_estonian_cs',
	[ 21] = 'latin2_hungarian_ci',
	[ 22] = 'koi8u_general_ci',
	[ 23] = 'cp1251_ukrainian_ci',
	[ 24] = 'gb2312_chinese_ci',
	[ 25] = 'greek_general_ci',
	[ 26] = 'cp1250_general_ci',
	[ 27] = 'latin2_croatian_ci',
	[ 28] = 'gbk_chinese_ci',
	[ 29] = 'cp1257_lithuanian_ci',
	[ 30] = 'latin5_turkish_ci',
	[ 31] = 'latin1_german2_ci',
	[ 32] = 'armscii8_general_ci',
	[ 33] = 'utf8_general_ci',
	[ 34] = 'cp1250_czech_cs',
	[ 35] = 'ucs2_general_ci',
	[ 36] = 'cp866_general_ci',
	[ 37] = 'keybcs2_general_ci',
	[ 38] = 'macce_general_ci',
	[ 39] = 'macroman_general_ci',
	[ 40] = 'cp852_general_ci',
	[ 41] = 'latin7_general_ci',
	[ 42] = 'latin7_general_cs',
	[ 43] = 'macce_bin',
	[ 44] = 'cp1250_croatian_ci',
	[ 45] = 'utf8mb4_general_ci',
	[ 46] = 'utf8mb4_bin',
	[ 47] = 'latin1_bin',
	[ 48] = 'latin1_general_ci',
	[ 49] = 'latin1_general_cs',
	[ 50] = 'cp1251_bin',
	[ 51] = 'cp1251_general_ci',
	[ 52] = 'cp1251_general_cs',
	[ 53] = 'macroman_bin',
	[ 54] = 'utf16_general_ci',
	[ 55] = 'utf16_bin',
	[ 56] = 'utf16le_general_ci',
	[ 57] = 'cp1256_general_ci',
	[ 58] = 'cp1257_bin',
	[ 59] = 'cp1257_general_ci',
	[ 60] = 'utf32_general_ci',
	[ 61] = 'utf32_bin',
	[ 62] = 'utf16le_bin',
	[ 63] = 'binary',
	[ 64] = 'armscii8_bin',
	[ 65] = 'ascii_bin',
	[ 66] = 'cp1250_bin',
	[ 67] = 'cp1256_bin',
	[ 68] = 'cp866_bin',
	[ 69] = 'dec8_bin',
	[ 70] = 'greek_bin',
	[ 71] = 'hebrew_bin',
	[ 72] = 'hp8_bin',
	[ 73] = 'keybcs2_bin',
	[ 74] = 'koi8r_bin',
	[ 75] = 'koi8u_bin',
	[ 76] = 'utf8_tolower_ci',
	[ 77] = 'latin2_bin',
	[ 78] = 'latin5_bin',
	[ 79] = 'latin7_bin',
	[ 80] = 'cp850_bin',
	[ 81] = 'cp852_bin',
	[ 82] = 'swe7_bin',
	[ 83] = 'utf8_bin',
	[ 84] = 'big5_bin',
	[ 85] = 'euckr_bin',
	[ 86] = 'gb2312_bin',
	[ 87] = 'gbk_bin',
	[ 88] = 'sjis_bin',
	[ 89] = 'tis620_bin',
	[ 90] = 'ucs2_bin',
	[ 91] = 'ujis_bin',
	[ 92] = 'geostd8_general_ci',
	[ 93] = 'geostd8_bin',
	[ 94] = 'latin1_spanish_ci',
	[ 95] = 'cp932_japanese_ci',
	[ 96] = 'cp932_bin',
	[ 97] = 'eucjpms_japanese_ci',
	[ 98] = 'eucjpms_bin',
	[ 99] = 'cp1250_polish_ci',
	[101] = 'utf16_unicode_ci',
	[102] = 'utf16_icelandic_ci',
	[103] = 'utf16_latvian_ci',
	[104] = 'utf16_romanian_ci',
	[105] = 'utf16_slovenian_ci',
	[106] = 'utf16_polish_ci',
	[107] = 'utf16_estonian_ci',
	[108] = 'utf16_spanish_ci',
	[109] = 'utf16_swedish_ci',
	[110] = 'utf16_turkish_ci',
	[111] = 'utf16_czech_ci',
	[112] = 'utf16_danish_ci',
	[113] = 'utf16_lithuanian_ci',
	[114] = 'utf16_slovak_ci',
	[115] = 'utf16_spanish2_ci',
	[116] = 'utf16_roman_ci',
	[117] = 'utf16_persian_ci',
	[118] = 'utf16_esperanto_ci',
	[119] = 'utf16_hungarian_ci',
	[120] = 'utf16_sinhala_ci',
	[121] = 'utf16_german2_ci',
	[122] = 'utf16_croatian_ci',
	[123] = 'utf16_unicode_520_ci',
	[124] = 'utf16_vietnamese_ci',
	[128] = 'ucs2_unicode_ci',
	[129] = 'ucs2_icelandic_ci',
	[130] = 'ucs2_latvian_ci',
	[131] = 'ucs2_romanian_ci',
	[132] = 'ucs2_slovenian_ci',
	[133] = 'ucs2_polish_ci',
	[134] = 'ucs2_estonian_ci',
	[135] = 'ucs2_spanish_ci',
	[136] = 'ucs2_swedish_ci',
	[137] = 'ucs2_turkish_ci',
	[138] = 'ucs2_czech_ci',
	[139] = 'ucs2_danish_ci',
	[140] = 'ucs2_lithuanian_ci',
	[141] = 'ucs2_slovak_ci',
	[142] = 'ucs2_spanish2_ci',
	[143] = 'ucs2_roman_ci',
	[144] = 'ucs2_persian_ci',
	[145] = 'ucs2_esperanto_ci',
	[146] = 'ucs2_hungarian_ci',
	[147] = 'ucs2_sinhala_ci',
	[148] = 'ucs2_german2_ci',
	[149] = 'ucs2_croatian_ci',
	[150] = 'ucs2_unicode_520_ci',
	[151] = 'ucs2_vietnamese_ci',
	[159] = 'ucs2_general_mysql500_ci',
	[160] = 'utf32_unicode_ci',
	[161] = 'utf32_icelandic_ci',
	[162] = 'utf32_latvian_ci',
	[163] = 'utf32_romanian_ci',
	[164] = 'utf32_slovenian_ci',
	[165] = 'utf32_polish_ci',
	[166] = 'utf32_estonian_ci',
	[167] = 'utf32_spanish_ci',
	[168] = 'utf32_swedish_ci',
	[169] = 'utf32_turkish_ci',
	[170] = 'utf32_czech_ci',
	[171] = 'utf32_danish_ci',
	[172] = 'utf32_lithuanian_ci',
	[173] = 'utf32_slovak_ci',
	[174] = 'utf32_spanish2_ci',
	[175] = 'utf32_roman_ci',
	[176] = 'utf32_persian_ci',
	[177] = 'utf32_esperanto_ci',
	[178] = 'utf32_hungarian_ci',
	[179] = 'utf32_sinhala_ci',
	[180] = 'utf32_german2_ci',
	[181] = 'utf32_croatian_ci',
	[182] = 'utf32_unicode_520_ci',
	[183] = 'utf32_vietnamese_ci',
	[192] = 'utf8_unicode_ci',
	[193] = 'utf8_icelandic_ci',
	[194] = 'utf8_latvian_ci',
	[195] = 'utf8_romanian_ci',
	[196] = 'utf8_slovenian_ci',
	[197] = 'utf8_polish_ci',
	[198] = 'utf8_estonian_ci',
	[199] = 'utf8_spanish_ci',
	[200] = 'utf8_swedish_ci',
	[201] = 'utf8_turkish_ci',
	[202] = 'utf8_czech_ci',
	[203] = 'utf8_danish_ci',
	[204] = 'utf8_lithuanian_ci',
	[205] = 'utf8_slovak_ci',
	[206] = 'utf8_spanish2_ci',
	[207] = 'utf8_roman_ci',
	[208] = 'utf8_persian_ci',
	[209] = 'utf8_esperanto_ci',
	[210] = 'utf8_hungarian_ci',
	[211] = 'utf8_sinhala_ci',
	[212] = 'utf8_german2_ci',
	[213] = 'utf8_croatian_ci',
	[214] = 'utf8_unicode_520_ci',
	[215] = 'utf8_vietnamese_ci',
	[223] = 'utf8_general_mysql500_ci',
	[224] = 'utf8mb4_unicode_ci',
	[225] = 'utf8mb4_icelandic_ci',
	[226] = 'utf8mb4_latvian_ci',
	[227] = 'utf8mb4_romanian_ci',
	[228] = 'utf8mb4_slovenian_ci',
	[229] = 'utf8mb4_polish_ci',
	[230] = 'utf8mb4_estonian_ci',
	[231] = 'utf8mb4_spanish_ci',
	[232] = 'utf8mb4_swedish_ci',
	[233] = 'utf8mb4_turkish_ci',
	[234] = 'utf8mb4_czech_ci',
	[235] = 'utf8mb4_danish_ci',
	[236] = 'utf8mb4_lithuanian_ci',
	[237] = 'utf8mb4_slovak_ci',
	[238] = 'utf8mb4_spanish2_ci',
	[239] = 'utf8mb4_roman_ci',
	[240] = 'utf8mb4_persian_ci',
	[241] = 'utf8mb4_esperanto_ci',
	[242] = 'utf8mb4_hungarian_ci',
	[243] = 'utf8mb4_sinhala_ci',
	[244] = 'utf8mb4_german2_ci',
	[245] = 'utf8mb4_croatian_ci',
	[246] = 'utf8mb4_unicode_520_ci',
	[247] = 'utf8mb4_vietnamese_ci',
	[248] = 'gb18030_chinese_ci',
	[249] = 'gb18030_bin',
	[250] = 'gb18030_unicode_520_ci',
	[255] = 'utf8mb4_0900_ai_ci',
	[256] = 'utf8mb4_de_pb_0900_ai_ci',
	[257] = 'utf8mb4_is_0900_ai_ci',
	[258] = 'utf8mb4_lv_0900_ai_ci',
	[259] = 'utf8mb4_ro_0900_ai_ci',
	[260] = 'utf8mb4_sl_0900_ai_ci',
	[261] = 'utf8mb4_pl_0900_ai_ci',
	[262] = 'utf8mb4_et_0900_ai_ci',
	[263] = 'utf8mb4_es_0900_ai_ci',
	[264] = 'utf8mb4_sv_0900_ai_ci',
	[265] = 'utf8mb4_tr_0900_ai_ci',
	[266] = 'utf8mb4_cs_0900_ai_ci',
	[267] = 'utf8mb4_da_0900_ai_ci',
	[268] = 'utf8mb4_lt_0900_ai_ci',
	[269] = 'utf8mb4_sk_0900_ai_ci',
	[270] = 'utf8mb4_es_trad_0900_ai_ci',
	[271] = 'utf8mb4_la_0900_ai_ci',
	[273] = 'utf8mb4_eo_0900_ai_ci',
	[274] = 'utf8mb4_hu_0900_ai_ci',
	[275] = 'utf8mb4_hr_0900_ai_ci',
	[277] = 'utf8mb4_vi_0900_ai_ci',
	[278] = 'utf8mb4_0900_as_cs',
	[279] = 'utf8mb4_de_pb_0900_as_cs',
	[280] = 'utf8mb4_is_0900_as_cs',
	[281] = 'utf8mb4_lv_0900_as_cs',
	[282] = 'utf8mb4_ro_0900_as_cs',
	[283] = 'utf8mb4_sl_0900_as_cs',
	[284] = 'utf8mb4_pl_0900_as_cs',
	[285] = 'utf8mb4_et_0900_as_cs',
	[286] = 'utf8mb4_es_0900_as_cs',
	[287] = 'utf8mb4_sv_0900_as_cs',
	[288] = 'utf8mb4_tr_0900_as_cs',
	[289] = 'utf8mb4_cs_0900_as_cs',
	[290] = 'utf8mb4_da_0900_as_cs',
	[291] = 'utf8mb4_lt_0900_as_cs',
	[292] = 'utf8mb4_sk_0900_as_cs',
	[293] = 'utf8mb4_es_trad_0900_as_cs',
	[294] = 'utf8mb4_la_0900_as_cs',
	[296] = 'utf8mb4_eo_0900_as_cs',
	[297] = 'utf8mb4_hu_0900_as_cs',
	[298] = 'utf8mb4_hr_0900_as_cs',
	[300] = 'utf8mb4_vi_0900_as_cs',
	[303] = 'utf8mb4_ja_0900_as_cs',
	[304] = 'utf8mb4_ja_0900_as_cs_ks',
	[305] = 'utf8mb4_0900_as_ci',
	[306] = 'utf8mb4_ru_0900_ai_ci',
	[307] = 'utf8mb4_ru_0900_as_cs',
	[308] = 'utf8mb4_zh_0900_as_cs',
	[309] = 'utf8mb4_0900_bin',
}

local collation_codes = index(collation_names)

local default_collations = {
	big5     = 'big5_chinese_ci',
	dec8     = 'dec8_swedish_ci',
	cp850    = 'cp850_general_ci',
	hp8      = 'hp8_english_ci',
	koi8r    = 'koi8r_general_ci',
	latin1   = 'latin1_swedish_ci',
	latin2   = 'latin2_general_ci',
	swe7     = 'swe7_swedish_ci',
	ascii    = 'ascii_general_ci',
	ujis     = 'ujis_japanese_ci',
	sjis     = 'sjis_japanese_ci',
	hebrew   = 'hebrew_general_ci',
	tis620   = 'tis620_thai_ci',
	euckr    = 'euckr_korean_ci',
	koi8u    = 'koi8u_general_ci',
	gb2312   = 'gb2312_chinese_ci',
	greek    = 'greek_general_ci',
	cp1250   = 'cp1250_general_ci',
	gbk      = 'gbk_chinese_ci',
	latin5   = 'latin5_turkish_ci',
	armscii8 = 'armscii8_general_ci',
	utf8     = 'utf8_general_ci',
	ucs2     = 'ucs2_general_ci',
	cp866    = 'cp866_general_ci',
	keybcs2  = 'keybcs2_general_ci',
	macce    = 'macce_general_ci',
	macroman = 'macroman_general_ci',
	cp852    = 'cp852_general_ci',
	latin7   = 'latin7_general_ci',
	cp1251   = 'cp1251_general_ci',
	utf16    = 'utf16_general_ci',
	utf16le  = 'utf16le_general_ci',
	cp1256   = 'cp1256_general_ci',
	cp1257   = 'cp1257_general_ci',
	utf32    = 'utf32_general_ci',
	binary   = 'binary',
	geostd8  = 'geostd8_general_ci',
	cp932    = 'cp932_japanese_ci',
	eucjpms  = 'eucjpms_japanese_ci',
	gb18030  = 'gb18030_chinese_ci',
	utf8mb4  = 'utf8mb4_0900_ai_ci',
}

local buffer_type_names = {
	[  0] = 'decimal',
	[  1] = 'tiny',
	[  2] = 'short',
	[  3] = 'long',
	[  4] = 'float',
	[  5] = 'double',
	[  6] = 'null',
	[  7] = 'timestamp',
	[  8] = 'longlong',
	[  9] = 'int24',
	[ 10] = 'date',
	[ 11] = 'time',
	[ 12] = 'datetime',
	[ 13] = 'year',
	[ 15] = 'varchar',
	[ 16] = 'bit',
	[246] = 'newdecimal',
	[247] = 'enum',
	[248] = 'set',
	[249] = 'tiny_blob',
	[250] = 'medium_blob',
	[251] = 'long_blob',
	[252] = 'blob',
	[253] = 'var_string',
	[254] = 'string',
	[255] = 'geometry',
}

local num_types = {
	tiny        = 'tinyint',
	short       = 'shortint',
	long        = 'int',
	int24       = 'mediumint',
	longlong    = 'bigint',
	newdecimal  = 'decimal',
}

local bin_types = {
	tiny_blob   = 'tinyblob',
	medium_blob = 'mediumblob',
	long_blob   = 'longblob',
	blob        = 'blob',
	var_string  = 'varbinary',
	string      = 'binary',
}

local text_types = {
	tiny_blob   = 'tinytext',
	medium_blob = 'mediumtext',
	long_blob   = 'longtext',
	blob        = 'text',
	var_string  = 'varchar',
	string      = 'char',
}

local string_types = {
	string=1,
	varchar=1,
	var_string=1,
	enum=1,
	set=1,
	long_blob=1,
	blob=1,
	tiny_blob=1,
	geometry=1,
	bit=1,
	decimal=1,
	newdecimal=1,
}

local conn = {}
local conn_mt = {__index = conn}

local from_text_converters = {
	tinyint   = tonumber,
	shortint  = tonumber,
	mediumint = tonumber,
	int       = tonumber,
	bigint    = tonumber,
	year      = tonumber,
	float     = tonumber,
	double    = tonumber,
}

local function return_arg1(v) return v end

assert(ffi.abi'le')

local function buf_len(buf)
	local _, _, n = buf()
	buf(-n)
	return n
end

local  i8_ct = ffi.typeof  'int8_t*'
local i16_ct = ffi.typeof 'int16_t*'
local u16_ct = ffi.typeof'uint16_t*'
local i32_ct = ffi.typeof' int32_t*'
local u32_ct = ffi.typeof'uint32_t*'
local i64_ct = ffi.typeof 'int64_t*'
local u64_ct = ffi.typeof'uint64_t*'
local f64_ct = ffi.typeof'double*'
local f32_ct = ffi.typeof'float*'

local function get_u8(buf)
	local p, i = buf(1)
	return p[i]
end

local function get_i8(buf)
	local p, i = buf(1)
	return ffi.cast(i8_ct, p+i)[0]
end

local function get_u16(buf)
	local p, i = buf(2)
	return ffi.cast(u16_ct, p+i)[0]
end

local function get_i16(buf)
	local p, i = buf(2)
	return ffi.cast(i16_ct, p+i)[0]
end

local function get_u24(buf)
	local p, i = buf(3)
	local a, b, c = p[i], p[i+1], p[i+2]
	return bor(a, shl(b, 8), shl(c, 16))
end

local function get_u32(buf)
	local p, i = buf(4)
	return ffi.cast(u32_ct, p+i)[0]
end

local function get_i32(buf)
	local p, i = buf(4)
	return ffi.cast(i32_ct, p+i)[0]
end

local function get_u64(buf)
	local p, i = buf(8)
	return tonumber(ffi.cast(u64_ct, p+i)[0])
end

local function get_i64(buf)
	local p, i = buf(8)
	return tonumber(ffi.cast(i64_ct, p+i)[0])
end

local function get_f64(buf)
	local p, i = buf(8)
	return tonumber(ffi.cast(f64_ct, p+i)[0])
end

local function get_f32(buf)
	local p, i = buf(4)
	return tonumber(ffi.cast(f32_ct, p+i)[0])
end

local function get_uint(buf) --length-encoded int
	local c = get_u8(buf)
	if c < 0xfb then
		return c
	elseif c == 0xfb then --NULL string
		return nil
	elseif c == 0xfc then
		return get_u16(buf)
	elseif c == 0xfd then
		return get_u24(buf)
	elseif c == 0xfe then
		return get_u64(buf)
	else
		buf(1/0, 'invalid length-encoded int')
	end
end

local function get_cstring(buf)
	local p, i0 = buf(0)
	while true do
		local _, i = buf(1)
		if p[i] == 0 then
			return ffi.string(p+i0, i-i0)
		end
		i = i + 1
	end
end

local function get_str(buf) --length-encoded string
	local slen = get_uint(buf)
	if not slen then return nil end
	local p, i = buf(slen)
	return ffi.string(p+i, slen)
end

local function get_bytes(buf, len) --fixed-length string
	local p, i, len = buf(len)
	return ffi.string(p+i, len)
end

local function get_datetime(buf, date_format)
	local len = get_u8(buf)
	if len == 0 then
		return date_format == '*t'
			and {year = 0, month = 0, day = 0}
			or date_format and format(date_format, 0, 0, 0, 0, 0, 0, 0)
			or '0000-00-00'
	end
	local y = get_u16(buf)
	local m = get_u8(buf)
	local d = get_u8(buf)
	if len == 4 then
		return date_format == '*t'
			and {year = y, month = m, day = d}
			or format(date_format or '%04d-%02d-%02d', y, m, d, 0, 0, 0, 0)
	end
	local H = get_u8(buf)
	local M = get_u8(buf)
	local S = get_u8(buf)
	local ms = len == 7 and 0 or get_u32(buf)
	return date_format == '*t'
		and {year = y, month = m, day = d, hour = H, min = M, sec = S + ms / 10^6}
		or format(date_format or (len == 7
				and '%04d-%02d-%02d %02d:%02d:%02d'
				 or '%04d-%02d-%02d %02d:%02d:%02d.%06d'),
			y, m, d, H, M, S, ms)
end

local function get_time(buf, time_format)
	local len = get_u8(buf)
	if len == 0 then
		return {days = 0, hour = 0, min = 0, sec = 0}
	end
	local sign = get_u8(buf) == 1 and -1 or 1
	local days = get_u4(buf) * sign
	local H = get_u8(buf)
	local M = get_u8(buf)
	local S = get_u8(buf)
	local ms = len == 8 and 0 or get_u32(buf)
	return time_format == '*t'
		and {days = days, hour = H, min = M, sec = S + ms / 10^6}
		 or time_format == '*s' and days * 24 * 3600 + H * 3600 + M * 60 + S + ms / 10^6
		 or format(time_format or (len == 8
			and '%dd %02d:%02d:%02d'
			 or '%dd %02d:%02d:%02d.%06d'), days, H, M, S, ms)
end

local function set_datetime(buf, t)

end

local function set_time(buf, t)

end

local function set_u8(buf, x)
	local p, i = buf(1)
	assert(x >= 0 and x < 2^8)
	p[i] = x
end

local function set_i8(buf, x)
	local p, i = buf(1)
	assert(x >= -127 and x <= 128)
	ffi.cast(i8_ct, p+i)[0] = x
end

local function set_u24(buf, x)
	local p, i = buf(3)
	assert(x >= 0 and x < 2^24)
	p[i+0] = band(    x     , 0xff)
	p[i+1] = band(shr(x,  8), 0xff)
	p[i+2] = band(shr(x, 16), 0xff)
end

local function set_u32(buf, x)
	local p, i = buf(4)
	assert(x >= 0 and x < 2^32)
	ffi.cast(u32_ct, p+i)[0] = x
end

local function set_i32(buf, x)
	local p, i = buf(4)
	assert(x >= -(2^31-1) and x <= 2^31)
	ffi.cast(i32_ct, p+i)[0] = x
end

local function set_u64(buf, x)
	local p, i = buf(8)
	assert(x >= 0 and x <= 2^52)
	ffi.cast(u64_ct, p+i)[0] = x
end

local function set_i64(buf, x)
	local p, i = buf(8)
	assert(x >= -(2^51-1) and x <= 2^51)
	ffi.cast(i64_ct, p+i)[0] = x
end

local function set_f64(buf, x)
	local p, i = buf(8)
	ffi.cast(f64_ct, p+i)[0] = x
end

local function set_f32(buf, x)
	local p, i = buf(4)
	ffi.cast(f32_ct, p+i)[0] = x
end

local function set_uint(buf, x) --length-encoded int
	assert(x >= 0)
	if x < 0xfb then
		set_u8(buf, x)
	elseif x < 2^16 then
		set_u8(buf, 0xfc)
		set_u16(buf, x)
	elseif x < 2^24 then
		set_u8(buf, 0xfd)
		set_u24(buf, x)
	else
		set_u8(buf, 0xfe)
		set_u64(buf, x)
	end
end

local function set_cstring(buf, s)
	local p, i = buf(#s+1)
	ffi.copy(p+i, s)
end

local function set_bytes(buf, s, len)
	len = len or #s
	local p, i = buf(len)
	ffi.copy(p+i, s, len)
end

local function set_str(buf, s)
	set_uint(#s)
	set_bytes(buf, s)
end

local function set_token(buf, password, scramble)
	if password == '' then
		return ''
	end
	local stage1 = sha1(password)
	local stage2 = sha1(stage1)
	local stage3 = sha1(scramble .. stage2)
	local n = #stage1
	set_u8(buf, n)
	local p, pi = buf(n)
	for i = 1, n do
		 p[pi+i-1] = bxor(strbyte(stage3, i), strbyte(stage1, i))
	end
end

local function send_buffer(min_capacity)
	local arr = dynarray('uint8_t[?]', min_capacity)
	local i = 0
	return function(n)
		local p = arr(i+n)
		i = i + n
		return p, i-n
	end
end

local function send_packet(self, send_buf)
	local send_buf, send_len = send_buf(0)
	self.packet_no = self.packet_no + 1
	local buf = send_buffer(4)
	set_u24(buf, send_len)
	set_u8(buf, band(self.packet_no, 0xff))
	check_io(self, self.tcp:send(buf(0)))
	check_io(self, self.tcp:send(send_buf, send_len))
end

local function recv(self, sz)
	local buf = self.buf
	if not buf then
		buf = buffer'uint8_t[?]'
		self.buf = buf
	end
	local buf = buf(sz)
	check_io(self, self.tcp:recvall(buf, sz))
	local i = 0
	return function(n, err)
		n = n or sz-i
		check(self, i + n <= sz, err or 'short read')
		i = i + n
		return buf, i-n, n
	end
end

local function recv_packet(self)
	local buf = recv(self, 4) --packet header
	local len = get_u24(buf)
	check(self, len > 0, 'empty packet')
	check(self, len <= self.max_packet_size, 'packet too big')
	self.packet_no = get_u8(buf)
	local buf = recv(self, len)
	local field_count = get_u8(buf)
	buf(-1) --peek
	if     field_count == 0x00 then typ = 'OK'
	elseif field_count == 0xff then typ = 'ERR'
	elseif field_count == 0xfe then typ = 'EOF'
	else                            typ = 'DATA'
	end
	return typ, buf
end

local function get_name(buf)
	local s = get_str(buf)
	return s ~= '' and s:lower() or nil
end

local function get_eof_packet(buf)
	local _             = get_u8(buf) --status: EOF
	local warning_count = get_u16(buf)
	local status_flags  = get_u16(buf)
	return warning_count, status_flags
end

local UNSIGNED_FLAG = 32

--NOTE: MySQL doesn't give enough metadata to generate a form in a UI,
--you'll have to query `information_schema` to get the rest like enum values
--and defaults. So we only keep enough info for formatting the values.
local function get_field_packet(buf)
	local col = {}
	local _              = get_name(buf) --always "def"
	col.schema           = get_name(buf)
	col.table            = get_name(buf)
	col.origin_table     = get_name(buf)
	col.name             = get_name(buf)
	col.origin_name      = get_name(buf)
	local _              = get_uint(buf) --0x0c
	local collation      = get_u16(buf)
	col.max_char_w       = get_u32(buf)
	local buf_type_code  = get_u8(buf)
	local flags          = get_u16(buf)
	local decimals       = get_u8(buf)
	local buf_type       = buffer_type_names[buf_type_code]
	if collation == 63 then
		col.type = bin_types[buf_type]
			or num_types[buf_type]
			or buf_type
	else
		col.type = text_types[buf_type]
		col.collation = collation_names[collation]
		col.charset = col.collation and col.collation:match'^[^_]+'
	end
	if col.type == 'decimal' then
		col.decimals = decimals
	end
	col.buffer_type = buf_type
	col.buffer_type_code = buf_type_code
	col.unsigned = band(flags, UNSIGNED_FLAG) ~= 0 or nil
	return col
end

local function recv_field_packets(self, field_count)
	local fields = {}
	for i = 1, field_count do
		local typ, buf = recv_packet(self)
		check(self, typ == 'DATA', 'bad packet type')
		local field = get_field_packet(buf)
		field.index = i
		fields[i] = field
		fields[field.name] = field
	end
	if field_count > 0 then
		local typ, buf = recv_packet(self)
		check(self, typ == 'EOF', 'bad packet type')
		get_eof_packet(buf)
	end
	return fields
end

local function get_err_packet(buf)
	local _      = get_u8(buf)
	local errno  = get_u16(buf)
	local marker = get_u8(buf)
	local sqlstate = strchar(marker) == '#' and get_bytes(buf, 5) or nil
	local message = get_bytes(buf)
	message = message:gsub('You have an error in your SQL syntax; '
		..'check the manual that corresponds to your MySQL server version '
		..'for the right syntax to use near ', 'Syntax error: ')
	return message, errno, sqlstate
end

function mysql.connect(opt)

	local tcp = opt and opt.tcp or require'sock'.tcp
	local tcp = check_io(self, tcp())
	local self = setmetatable({tcp = tcp}, conn_mt)

	self.max_packet_size = opt.max_packet_size or 16 * 1024 * 1024 --16 MB
	local ok, err

	local database = opt.database or ''
	local user = opt.user or ''

	local collation = 0 --default
	if opt.collation then
		collation = assert(collation_codes[opt.collation], 'invalid collation')
	elseif opt.charset then
		collation = assert(default_collations[opt.charset], 'invalid charset')
		collation = assert(collation_codes[collation])
	end

	local host = opt.host
	local port = opt.port or 3306
	check_io(self, self.tcp:connect(host, port))

	local typ, buf = recv_packet(self)
	if typ == 'ERR' then
		return nil, get_err_packet(buf)
	end
	self.protocol_ver       = get_u8(buf)
	self.server_ver         = get_cstring(buf)
	self.thread_id          = get_u32(buf)
	local scramble          = get_bytes(buf, 8)
	buf(1) --filler
	local capabilities      = get_u16(buf)
	self.server_lang        = get_u8(buf)
	self.server_status      = get_u16(buf)
	local more_capabilities = get_u16(buf)
	capabilities = bor(capabilities, shl(more_capabilities, 16))
	get_bytes(buf, 1 + 10)
	local scramble_part2 = get_bytes(buf, 21 - 8 - 1)
	scramble = scramble .. scramble_part2
	local client_flags = 0x3f7cf
	local ssl_verify = opt.ssl_verify
	local use_ssl = opt.ssl or ssl_verify

	local buf = send_buffer(64)
	if use_ssl then
		check(self, band(capabilities, CLIENT_SSL) ~= 0, 'ssl disabled on server')
		set_u32(buf, bor(client_flags, CLIENT_SSL))
		set_u32(buf, self.max_packet_size)
		set_u8(buf, collation)
		buf(23)
		send_packet(self, buf)
		check_io(self, self.tcp:sslhandshake(false, nil, ssl_verify))
	end
	set_u32(buf, client_flags)
	set_u32(buf, self.max_packet_size)
	set_u8(buf, collation)
	buf(23)
	set_cstring(buf, user)
	set_token(buf, opt.password or '', scramble)
	set_cstring(buf, database)
	send_packet(self, buf)

	local typ, buf = recv_packet(self)
	if typ == 'ERR' then
		return nil, get_err_packet(buf)
	elseif typ == 'EOF' then
		return nil, 'old pre-4.1 authentication protocol not supported'
	end
	check(self, typ == 'OK', 'bad packet type')
	self.state = 'ready'
	return self
end
conn.connect = protect(conn.connect)

function conn:close()
	if self.state then
		local buf = send_buffer(1)
		set_u8(buf, COM_QUIT)
		send_packet(self, buf)
		check_io(self, self.tcp:close())
		self.state = nil
	end
	return true
end
conn.close = protect(conn.close)

function conn:send_query(query)
	assert(self.state == 'ready')
	self.packet_no = -1
	local buf = send_buffer(1 + #query)
	set_u8(buf, COM_QUERY)
	set_bytes(buf, query)
	send_packet(self, buf)
	self.state = 'read'
	return true
end
conn.send_query = protect(conn.send_query)

function conn:read_result(opt)
	assert(self.state == 'read' or self.state == 'read_binary')
	local typ, buf = recv_packet(self)
	if typ == 'ERR' then
		self.state = 'ready'
		return nil, get_err_packet(buf)
	elseif typ == 'OK' then
		local res = {}
		res.affected_rows = get_uint(buf)
		res.insert_id     = get_uint(buf)
		res.server_status = get_u16(buf)
		res.warning_count = get_u16(buf)
		res.message       = get_str(buf)
		res.insert_id = repl(res.insert_id, 0, nil)
		if band(res.server_status, SERVER_MORE_RESULTS_EXISTS) ~= 0 then
			return res, 'again'
		else
			self.state = 'ready'
			return res
		end
	end
	check(self, typ == 'DATA', 'bad packet type')

	local field_count = get_uint(buf)
	local extra = buf_len(buf) > 0 and get_uint(buf) or nil

	local cols = recv_field_packets(self, field_count)

	local compact     = opt and opt.compact
	local to_array    = opt and opt.to_array and #cols == 1
	local null_value  = opt and opt.null_value
	local datetime_format = opt and opt.datetime_format
	local date_format     = opt and opt.date_format
	local time_format     = opt and opt.time_format

	local rows = {}
	local i = 0
	while true do
		local typ, buf = recv_packet(self)

		if typ == 'EOF' then
			local _, status_flags = get_eof_packet(buf)
			if band(status_flags, SERVER_MORE_RESULTS_EXISTS) ~= 0 then
				return rows, 'again', cols
			end
			break
		end

		local row = not to_array and {} or nil

		if self.state == 'read_binary' then
			check(get_u8(buf) == 0, 'invalid row packet')
			local nulls_len = math.floor((#cols + 7 + 2) / 8)
			local nulls, nulls_offset = buf(nulls_len)
			for i, col in ipairs(cols) do
				local null_byte = shr(i-1+2, 3) + nulls_offset
				local null_bit = band(i-1+2, 7)
				local is_null = band(nulls[null_byte], shl(1, null_bit)) ~= 0
				local v
				if not is_null then
					local bt = col.buffer_type
					local unsigned = col.unsigned
					if string_types[bt] then
						v = get_str(buf)
					elseif bt == 'longlong' then
						v = unsigned and get_u64(buf) or get_i64(buf)
					elseif bt == 'int24' or bt == 'long' then
						v = unsigned and get_u32(buf) or get_i32(buf)
					elseif bt == 'year' then
						v = unsigned and get_u16(buf) or get_i16(buf)
					elseif bt == 'tiny' then
						v = unsigned and get_u8(buf) or get_i8(buf)
					elseif bt == 'double' then
						v = get_f64(buf)
					elseif bt == 'float' then
						v = get_f32(buf)
					elseif bt == 'date' or bt == 'datetime' or bt == 'timestamp' then
						v = get_datetime(buf, bt == 'date' and date_format or datetime_format)
					elseif bt == 'time' then
						v = get_time(buf, time_format)
					else
						check(self, false, 'unsupported param type '..bt)
					end
				else
					v = null_value
				end
				if to_array then
					row = v
				elseif compact then
					row[i] = v
				else
					row[col.name] = v
				end
			end
		else
			for i, col in ipairs(cols) do
				local v = get_str(buf)
				if v ~= nil then
					local convert = from_text_converters[col.type]
					if convert then
						v = convert(v)
					end
				else
					v = null_value
				end
				if to_array then
					row = v
				elseif compact then
					row[i] = v
				else
					row[col.name] = v
				end
			end
		end

		i = i + 1
		rows[i] = row
	end

	self.state = 'ready'
	return rows, nil, cols
end
conn.read_result = protect(conn.read_result)

function conn:query(query, opt)
	local bytes, err, errcode = self:send_query(query)
	if not bytes then return nil, err, errcode end
	return self:read_result(opt)
end

local stmt = {}

local cursor_types = {
	no_cursor  = 0x00,
	read_only  = 0x01,
	update     = 0x02,
	scrollable = 0x04,
}

function conn:prepare(query, cursor_type)
	assert(self.state == 'ready')
	self.packet_no = -1
	local buf = send_buffer(1 + #query)
	set_u8(buf, COM_STMT_PREPARE)
	set_bytes(buf, query)
	send_packet(self, buf)

	local typ, buf = recv_packet(self)
	if typ == 'ERR' then
		return nil, get_err_packet(buf)
	end
	check(self, typ == 'OK', 'bad packet type')
	buf(1) --status
	local stmt = update({conn = self}, stmt)
	stmt.id            = get_u32(buf)
	local col_count    = get_u16(buf)
	local param_count  = get_u16(buf)
	buf(1) --filler
	stmt.warning_count = get_u16(buf)
	stmt.params = recv_field_packets(self, param_count)
	stmt.cols = recv_field_packets(self, col_count)
	stmt.cursor_type = assert(cursor_types[cursor_type or 'no_cursor'])
	return stmt
end
conn.prepare = protect(conn.prepare)

function stmt:free()
	local self, stmt = self.conn, self
	assert(self.state == 'ready')
	self.packet_no = -1
	local buf = send_buffer(5)
	set_u8(buf, COM_STMT_CLOSE)
	set_u32(buf, stmt.id)
	return true
end
stmt.free = protect(stmt.free)

function stmt:exec(...)
	local self, stmt = self.conn, self
	assert(self.state == 'ready')
	self.packet_no = -1
	local buf = send_buffer(64)
	set_u8(buf, COM_STMT_EXECUTE)
	set_u32(buf, stmt.id)
	set_u8(buf, stmt.cursor_type)
	set_u32(buf, 1) --iteration-count, must be 1
	if #stmt.params > 0 then
		local nulls_len = math.floor((#stmt.params + 7) / 8)
		local nulls = ffi.new('uint8_t[?]', nulls_len)
		for i = 1, #stmt.params do
			local val = select(i, ...)
			if val == nil then
				local byte = shr(i-1, 3)
				local bit = band(i-1, 7)
				nulls[byte] = bor(nulls[byte], shl(1, bit))
			end
		end
		set_bytes(buf, nulls, nulls_len)
		set_u8(buf, 1) --new-params-bound-flag
		for i, param in ipairs(stmt.params) do
			set_u8(buf, param.buffer_type_code)
			set_u8(buf, param.unsigned and 0x80 or 0)
		end
		for i, param in ipairs(stmt.params) do
			local val = select(i, ...)
			if val ~= nil then
				local bt = param.buffer_type
				local unsigned = param.unsigned
				if string_types[bt] then
					set_str(buf, tostring(val))
				elseif bt == 'longlong' then
					if unsigned then
						set_u64(buf, val)
					else
						set_i64(buf, val)
					end
				elseif bt == 'int24' or bt == 'long' then
					if unsigned then
						assert(val >= 0 and val < (bt == 'int24' and 2^24 or 2^32))
						set_u32(buf, val)
					else
						if bt == 'int24' then
							assert(val >= -(2^23-1) and val <= 2^23-1)
						else
							assert(val >= -(2^31-1) and val <= 2^31)
						end
						set_i32(buf, val)
					end
				elseif bt == 'year' then
					if unsigned then
						set_u16(buf, val)
					else
						set_i16(buf, val)
					end
				elseif bt == 'tiny' then
					if unsigned then
						set_u8(buf, val)
					else
						set_i8(buf, val)
					end
				elseif bt == 'double' then
					set_f64(buf, val)
				elseif bt == 'float' then
					set_f32(buf, val)
				elseif bt == 'date' or bt == 'datetime' or bt == 'timestamp' then
					set_datetime(buf, val)
				elseif bt == 'time' then
					set_time(buf, val)
				else
					check(self, false, 'unsupported param type '..bt)
				end
			end
		end

	end
	send_packet(self, buf)
	self.state = 'read_binary'
	return true
end
stmt.exec = protect(stmt.exec)

local qmap = {
	['\0' ] = '\\0',
	['\b' ] = '\\b',
	['\n' ] = '\\n',
	['\r' ] = '\\r',
	['\t' ] = '\\t',
	['\26'] = '\\Z',
	['\\' ] = '\\\\',
	['\'' ] = '\\\'',
	['\"' ] = '\\"',
}
function mysql.quote(s)
	return s:gsub('[%z\b\n\r\t\26\\\'\"]', qmap)
end


if not ... then --demo

	local sock = require'sock'
	local pp = require'pp'
	sock.run(function()
		local conn = mysql.connect{
			host = '127.0.0.1',
			port = 3307,
			user = 'root',
			password = 'abcd12',
			database = 'sp',
		}
		pp(conn:query'select * from val where val = 1')
		local stmt = conn:prepare('select * from val where val = ?')
		assert(stmt:exec(1))
		pp(conn:read_result({datetime_format = '*t'}))
		assert(stmt:free())
	end)

end

return mysql
