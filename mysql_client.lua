
-- MySQL client protocol in Lua.
-- Written by Yichun Zhang (agentzh). BSD license.
-- Modified by Cosmin Apreutesei. Pulbic domain.

local ffi = require'ffi'
local bit = require'bit'
local sha1 = require'sha1'.sha1
local glue = require'glue'

local sub = string.sub
local strbyte = string.byte
local strchar = string.char
local format = string.format
local strrep = string.rep
local band = bit.band
local bxor = bit.bxor
local bor = bit.bor
local lshift = bit.lshift
local rshift = bit.rshift
local tohex = bit.tohex
local concat = table.concat

local buffer = glue.buffer
local index = glue.index
local repl = glue.repl

local ok, new_tab = pcall(require, 'table.new')
new_tab = ok and new_tab or function() return {} end

local mysql = {}

local COM_QUIT = 0x01
local COM_QUERY = 0x03
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

local type_names = {
	tiny        = 'tinyint',
	short       = 'shortint',
	long        = 'int',
	int24       = 'mediumint',
	longlong    = 'bigint',
	newdecimal  = 'decimal',
}

local bin_type_names = {
	tiny_blob   = 'tinyblob',
	medium_blob = 'mediumblob',
	long_blob   = 'longblob',
	blob        = 'blob',
	var_string  = 'varbinary',
	string      = 'binary',
}

local text_type_names = {
	tiny_blob   = 'tinytext',
	medium_blob = 'mediumtext',
	long_blob   = 'longtext',
	blob        = 'text',
	var_string  = 'varchar',
	string      = 'char',
}

local conn = {}
local mt = {__index = conn}

-- mysql field value type converters
local converters = {
	tinyint   = tonumber,
	shortint  = tonumber,
	mediumint = tonumber,
	int       = tonumber,
	bigint    = tonumber,
	year      = tonumber,
	float     = tonumber,
	double    = tonumber,
}

local function _get_byte2(data, i)
	local a, b = strbyte(data, i, i + 1)
	return bor(a, lshift(b, 8)), i + 2
end


local function _get_byte3(data, i)
	local a, b, c = strbyte(data, i, i + 2)
	return bor(a, lshift(b, 8), lshift(c, 16)), i + 3
end


local function _get_byte4(data, i)
	local a, b, c, d = strbyte(data, i, i + 3)
	return bor(a, lshift(b, 8), lshift(c, 16), lshift(d, 24)), i + 4
end


local function _get_byte8(data, i)
	local a, b, c, d, e, f, g, h = strbyte(data, i, i + 7)

	-- XXX workaround for the lack of 64-bit support in bitop:
	local lo = bor(a, lshift(b, 8), lshift(c, 16), lshift(d, 24))
	local hi = bor(e, lshift(f, 8), lshift(g, 16), lshift(h, 24))
	return lo + hi * 4294967296, i + 8

	-- return bor(a, lshift(b, 8), lshift(c, 16), lshift(d, 24), lshift(e, 32),
			   -- lshift(f, 40), lshift(g, 48), lshift(h, 56)), i + 8
end


local function _set_byte2(n)
	return strchar(band(n, 0xff), band(rshift(n, 8), 0xff))
end


local function _set_byte3(n)
	return strchar(band(n, 0xff),
				   band(rshift(n, 8), 0xff),
				   band(rshift(n, 16), 0xff))
end


local function _set_byte4(n)
	return strchar(band(n, 0xff),
				   band(rshift(n, 8), 0xff),
				   band(rshift(n, 16), 0xff),
				   band(rshift(n, 24), 0xff))
end


local function _from_cstring(data, i)
	local last = data:find('\0', i, true)
	if not last then
		return nil, nil
	end

	return sub(data, i, last - 1), last + 1
end


local function _to_cstring(data)
	return data .. '\0'
end


local function _to_binary_coded_string(data)
	return strchar(#data) .. data
end


local function _dump(data)
	local len = #data
	local bytes = new_tab(len, 0)
	for i = 1, len do
		bytes[i] = format('%x', strbyte(data, i))
	end
	return concat(bytes, ' ')
end


local function _dumphex(data)
	local len = #data
	local bytes = new_tab(len, 0)
	for i = 1, len do
		bytes[i] = tohex(strbyte(data, i), 2)
	end
	return concat(bytes, ' ')
end


local function _compute_token(password, scramble)
	if password == '' then
		return ''
	end

	local stage1 = sha1(password)
	local stage2 = sha1(stage1)
	local stage3 = sha1(scramble .. stage2)
	local n = #stage1
	local bytes = new_tab(n, 0)
	for i = 1, n do
		 bytes[i] = strchar(bxor(strbyte(stage3, i), strbyte(stage1, i)))
	end

	return concat(bytes)
end


local function _send_packet(self, req, size)
	local sock = self.sock

	self.packet_no = self.packet_no + 1

	-- print('packet no: ', self.packet_no)

	local packet = _set_byte3(size) .. strchar(band(self.packet_no, 255)) .. req

	-- print('sending packet: ', _dump(packet))

	-- print('sending packet... of size ' .. #packet)

	return sock:send(packet)
end

local function _recv(self, sz)
	local buf = self.buf
	if not buf then
		buf = buffer'char[?]'
		self.buf = buf
	end
	local buf = buf(sz)
	local ok, err = self.sock:recvall(buf, sz)
	if not ok then return nil, err end
	return ffi.string(buf, sz)
end

local function _recv_packet(self)
	local sock = self.sock

	local data, err = _recv(self, 4) -- packet header
	if not data then
		return nil, nil, 'failed to receive packet header: ' .. err
	end

	--print('packet header: ', _dump(data))

	local len, pos = _get_byte3(data, 1)

	--print('packet length: ', len)

	if len == 0 then
		return nil, nil, 'empty packet'
	end

	if len > self._max_packet_size then
		return nil, nil, 'packet size too big: ' .. len
	end

	local num = strbyte(data, pos)

	--print('recv packet: packet no: ', num)

	self.packet_no = num

	data, err = _recv(self, len)

	--print('receive returned')

	if not data then
		return nil, nil, 'failed to read packet content: ' .. err
	end

	--print('packet content: ', _dump(data))
	--print('packet content (ascii): ', data)

	local field_count = strbyte(data, 1)

	local typ
	if field_count == 0x00 then
		typ = 'OK'
	elseif field_count == 0xff then
		typ = 'ERR'
	elseif field_count == 0xfe then
		typ = 'EOF'
	else
		typ = 'DATA'
	end

	return data, typ
end


local function _from_length_coded_bin(data, pos)
	local first = strbyte(data, pos)

	--print('LCB: first: ', first)

	if not first then
		return nil, pos
	end

	if first >= 0 and first <= 250 then
		return first, pos + 1
	end

	if first == 251 then
		return nil, pos + 1
	end

	if first == 252 then
		pos = pos + 1
		return _get_byte2(data, pos)
	end

	if first == 253 then
		pos = pos + 1
		return _get_byte3(data, pos)
	end

	if first == 254 then
		pos = pos + 1
		return _get_byte8(data, pos)
	end

	return nil, pos + 1
end


local function _from_length_coded_str(data, pos)
	local len
	len, pos = _from_length_coded_bin(data, pos)
	if not len then
		return nil, pos
	end
	return sub(data, pos, pos + len - 1), pos + len
end

local function _parse_ok_packet(packet)
	local res = new_tab(0, 5)
	local pos

	res.affected_rows, pos = _from_length_coded_bin(packet, 2)

	--print('affected rows: ', res.affected_rows, ', pos:', pos)

	res.insert_id, pos = _from_length_coded_bin(packet, pos)

	if res.insert_id == 0 then
		res.insert_id = nil
	end

	--print('insert id: ', res.insert_id, ', pos:', pos)

	res.server_status, pos = _get_byte2(packet, pos)

	--print('server status: ', res.server_status, ', pos:', pos)

	res.warning_count, pos = _get_byte2(packet, pos)

	--print('warning count: ', res.warning_count, ', pos: ', pos)

	res.message = _from_length_coded_str(packet, pos)

	--print('message: ', res.message, ', pos:', pos)

	return res
end


local function _parse_eof_packet(packet)
	local pos = 2

	local warning_count, pos = _get_byte2(packet, pos)
	local status_flags = _get_byte2(packet, pos)

	return warning_count, status_flags
end


local function _parse_err_packet(packet)
	local errno, pos = _get_byte2(packet, 2)
	local marker = sub(packet, pos, pos)
	local sqlstate
	if marker == '#' then
		-- with sqlstate
		pos = pos + 1
		sqlstate = sub(packet, pos, pos + 5 - 1)
		pos = pos + 5
	end

	local message = sub(packet, pos)
	message = message:gsub('You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ', 'Syntax error: ')
	return errno, message, sqlstate
end


local function _parse_result_set_header_packet(packet)
	local field_count, pos = _from_length_coded_bin(packet, 1)

	local extra
	extra = _from_length_coded_bin(packet, pos)

	return field_count, extra
end

local function _parse_field(data, pos)
	local s, pos = _from_length_coded_str(data, pos)
	s = s and s ~= '' and s:lower() or nil
	return s, pos
end

local charset_bytes = {
	utf8 = 3,
	utf8mb4 = 4,
}

--NOTE: MySQL doesn't give enough info to make editable fields in a UI,
--you'll have to query `information_schema` to get the rest like enum values
--and defaults. So we only keep enough info to format read-only fields in a UI.
local function _parse_field_packet(data)
	local col = new_tab(0, 16)
	local catalog, pos = _parse_field(data, 1) --always "def"
	col.schema, pos = _parse_field(data, pos)
	col.table, pos = _parse_field(data, pos)
	col.origin_table, pos = _parse_field(data, pos)
	col.name, pos = _parse_field(data, pos)
	col.origin_name, pos = _parse_field(data, pos)
	pos = pos + 1 --ignore the filler
	local collation, pos = _get_byte2(data, pos)
	col.max_char_w, pos = _get_byte4(data, pos)
	local buffer_type = buffer_type_names[strbyte(data, pos)]
	if collation == 63 then
		col.type = bin_type_names[buffer_type]
			or type_names[buffer_type]
			or buffer_type
	else
		col.type = text_type_names[buffer_type]
		col.collation = collation_names[collation]
		col.charset = col.collation and col.collation:match'^[^_]+'
		col.max_char_w = col.max_char_w / (charset_bytes[col.charset] or 1)
	end
	pos = pos + 1
	local flags, pos = _get_byte2(data, pos)
	col.decimals = strbyte(data, pos) --for formatting only, not for editing!
	if col.type ~= 'decimal' and col.decimals == 0x1f then --varchar and floats
		col.decimals = nil
	end
	return col
end


local function _parse_row_data_packet(data, cols, compact, to_array, null_value)
	local pos = 1
	local ncols = #cols
	local row
	if not to_array then
		if compact then
			row = new_tab(ncols, 0)
		else
			row = new_tab(0, ncols)
		end
	end
	for i = 1, ncols do
		local value
		value, pos = _from_length_coded_str(data, pos)
		local col = cols[i]
		local typ = col.type
		local name = col.name

		--print('row field value: ', value, ', type: ', typ)

		if value ~= nil then
			local conv = converters[typ]
			if conv then
				value = conv(value)
			end
		else
			value = null_value
		end

		if to_array then
			return value
		end

		if compact then
			row[i] = value
		else
			row[name] = value
		end
	end

	return row
end


local function _recv_field_packet(self)
	local packet, typ, err = _recv_packet(self)
	if not packet then
		return nil, err
	end

	if typ == 'ERR' then
		local errno, msg, sqlstate = _parse_err_packet(packet)
		return nil, msg, errno, sqlstate
	end

	if typ ~= 'DATA' then
		return nil, 'bad field packet type: ' .. typ
	end

	-- typ == 'DATA'

	return _parse_field_packet(packet)
end


function mysql.new(self, opt)
	local tcp = opt and opt.tcp or require'sock'.tcp
	local sock, err = tcp()
	if not sock then
		return nil, err
	end
	return setmetatable({ sock = sock }, mt)
end


function conn:connect(opts)
	local sock = self.sock

	local max_packet_size = opts.max_packet_size
	if not max_packet_size then
		max_packet_size = 1024 * 1024 -- default 1 MB
	end
	self._max_packet_size = max_packet_size

	local ok, err

	local database = opts.database or ''
	local user = opts.user or ''

	local collation = 0 --default
	if opts.collation then
		collation = assert(collation_codes[opts.collation], 'invalid collation')
	elseif opts.charset then
		collation = assert(default_collations[opts.charset], 'invalid charset')
		collation = assert(collation_codes[collation])
	end

	local host = opts.host
	local port = opts.port or 3306
	ok, err, errcode = sock:connect(host, port)

	if not ok then
		return nil, err, errcode
	end

	local packet, typ, err = _recv_packet(self)
	if not packet then
		return nil, err
	end

	if typ == 'ERR' then
		local errno, msg, sqlstate = _parse_err_packet(packet)
		return nil, msg, errno, sqlstate
	end

	self.protocol_ver = strbyte(packet)

	--print('protocol version: ', self.protocol_ver)

	local server_ver, pos = _from_cstring(packet, 2)
	if not server_ver then
		return nil, 'bad handshake initialization packet: bad server version'
	end

	--print('server version: ', server_ver)

	self._server_ver = server_ver

	local thread_id, pos = _get_byte4(packet, pos)

	--print('thread id: ', thread_id)

	local scramble = sub(packet, pos, pos + 8 - 1)
	if not scramble then
		return nil, '1st part of scramble not found'
	end

	pos = pos + 9 -- skip filler

	-- two lower bytes
	local capabilities  -- server capabilities
	capabilities, pos = _get_byte2(packet, pos)

	-- print(format('server capabilities: %#x', capabilities))

	self._server_lang = strbyte(packet, pos)
	pos = pos + 1

	--print('server lang: ', self._server_lang)

	self._server_status, pos = _get_byte2(packet, pos)

	--print('server status: ', self._server_status)

	local more_capabilities
	more_capabilities, pos = _get_byte2(packet, pos)

	capabilities = bor(capabilities, lshift(more_capabilities, 16))

	--print('server capabilities: ', capabilities)

	-- local len = strbyte(packet, pos)
	local len = 21 - 8 - 1

	--print('scramble len: ', len)

	pos = pos + 1 + 10

	local scramble_part2 = sub(packet, pos, pos + len - 1)
	if not scramble_part2 then
		return nil, '2nd part of scramble not found'
	end

	scramble = scramble .. scramble_part2
	--print('scramble: ', _dump(scramble))

	local client_flags = 0x3f7cf;

	local ssl_verify = opts.ssl_verify
	local use_ssl = opts.ssl or ssl_verify

	if use_ssl then
		if band(capabilities, CLIENT_SSL) == 0 then
			return nil, 'ssl disabled on server'
		end

		-- send a SSL Request Packet
		local req = _set_byte4(bor(client_flags, CLIENT_SSL))
					.. _set_byte4(self._max_packet_size)
					.. strchar(collation)
					.. strrep('\0', 23)

		local packet_len = 4 + 4 + 1 + 23
		local bytes, err = _send_packet(self, req, packet_len)
		if not bytes then
			return nil, 'failed to send client authentication packet: ' .. err
		end

		local ok, err = sock:sslhandshake(false, nil, ssl_verify)
		if not ok then
			return nil, 'failed to do ssl handshake: ' .. (err or '')
		end
	end

	local password = opts.password or ''

	local token = _compute_token(password, scramble)

	--print('token: ', _dump(token))

	local req = _set_byte4(client_flags)
				.. _set_byte4(self._max_packet_size)
				.. strchar(collation)
				.. strrep('\0', 23)
				.. _to_cstring(user)
				.. _to_binary_coded_string(token)
				.. _to_cstring(database)

	local packet_len = 4 + 4 + 1 + 23 + #user + 1
		+ #token + 1 + #database + 1

	-- print('packet content length: ', packet_len)
	-- print('packet content: ', _dump(concat(req, '')))

	local bytes, err = _send_packet(self, req, packet_len)
	if not bytes then
		return nil, 'failed to send client authentication packet: ' .. err
	end

	--print('packet sent ', bytes, ' bytes')

	local packet, typ, err = _recv_packet(self)
	if not packet then
		return nil, 'failed to receive the result packet: ' .. err
	end

	if typ == 'ERR' then
		local errno, msg, sqlstate = _parse_err_packet(packet)
		return nil, msg, errno, sqlstate
	end

	if typ == 'EOF' then
		return nil, 'old pre-4.1 authentication protocol not supported'
	end

	if typ ~= 'OK' then
		return nil, 'bad packet type: ' .. typ
	end

	self.state = 'ready'

	return 1
end

function conn:close()
	local sock = assert(self.sock)

	self.state = nil

	local bytes, err = _send_packet(self, strchar(COM_QUIT), 1)
	if not bytes then
		return nil, err
	end

	return sock:close()
end

function conn:server_ver()
	return self._server_ver
end

function conn:send_query(query)
	assert(self.state == 'ready')
	local sock = assert(self.sock)

	self.packet_no = -1

	local cmd_packet = strchar(COM_QUERY) .. query
	local packet_len = 1 + #query

	local bytes, err = _send_packet(self, cmd_packet, packet_len)
	if not bytes then
		return nil, err
	end

	self.state = 'read'

	--print('packet sent ', bytes, ' bytes')

	return bytes
end

function conn:read_result(opt)
	assert(self.state == 'read')
	local sock = assert(self.sock)

	local packet, typ, err = _recv_packet(self)
	if not packet then
		return nil, err
	end

	if typ == 'ERR' then
		self.state = 'ready'

		local errno, msg, sqlstate = _parse_err_packet(packet)
		return nil, msg, errno, sqlstate
	end

	if typ == 'OK' then
		local res = _parse_ok_packet(packet)
		if res and band(res.server_status, SERVER_MORE_RESULTS_EXISTS) ~= 0 then
			return res, 'again'
		end

		self.state = 'ready'
		return res
	end

	if typ ~= 'DATA' then
		self.state = 'ready'

		return nil, 'packet type ' .. typ .. ' not supported'
	end

	-- typ == 'DATA'

	--print('read the result set header packet')

	local field_count, extra = _parse_result_set_header_packet(packet)

	--print('field count: ', field_count)

	local cols = new_tab(field_count, 0)
	for i = 1, field_count do
		local col, err, errno, sqlstate = _recv_field_packet(self)
		if not col then
			return nil, err, errno, sqlstate
		end

		col.index = i
		cols[i] = col
		cols[col.name] = col
	end

	local packet, typ, err = _recv_packet(self)
	if not packet then
		return nil, err
	end

	if typ ~= 'EOF' then
		return nil, 'unexpected packet type ' .. typ .. ' while eof packet is '
			.. 'expected'
	end

	-- typ == 'EOF'

	local compact    = opt and opt.compact
	local to_array   = opt and opt.to_array and #cols == 1
	local null_value = opt and opt.null_value

	local rows = new_tab(4, 0)
	local i = 0
	while true do
		--print('reading a row')

		packet, typ, err = _recv_packet(self)
		if not packet then
			return nil, err
		end

		if typ == 'EOF' then
			local warning_count, status_flags = _parse_eof_packet(packet)

			--print('status flags: ', status_flags)

			if band(status_flags, SERVER_MORE_RESULTS_EXISTS) ~= 0 then
				return rows, 'again', cols
			end

			break
		end

		-- if typ ~= 'DATA' then
			-- return nil, 'bad row packet type: ' .. typ
		-- end

		-- typ == 'DATA'

		local row = _parse_row_data_packet(packet, cols, compact, to_array, null_value)

		i = i + 1
		rows[i] = row
	end

	self.state = 'ready'

	return rows, nil, cols
end

function conn:query(query, opt)
	local bytes, err, errcode = self:send_query(query)
	if not bytes then return nil, err, errcode end
	return self:read_result(opt)
end

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

return mysql
