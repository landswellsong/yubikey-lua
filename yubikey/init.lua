local _M = {};

local aeslua = require "aeslua";
local ciphermode = require "aeslua.ciphermode";
local crc16 = require "crc16";

local modhex2hex;
do
	local modhex_map = {};
	local modhex_chars = "cbdefghijklnrtuv";
	for i=1,16 do
		modhex_map[modhex_chars:sub(i,i)] = ("%x"):format(i-1);
	end
	function modhex2hex(modhex)
		if modhex then
			return (modhex:gsub(".", modhex_map));
		end
	end
end
_M.modhex2hex = modhex2hex;

local function hex2bin(hex)
	if hex then
		return (hex:gsub("..", function (c) return string.char(tonumber(c, 16)); end));
	end
end
_M.hex2bin = hex2bin;

local function bin2hex(bin)
	if bin then
		return (bin:gsub(".", function (b) return ("%02x"):format(b:byte()); end));
	end
end
_M.bin2hex = bin2hex;

local otp_parser = {};
local otp_parser_mt = { __index = otp_parser };

function _M.new_fetch_key_hex(fetchkeyhex)
	return function (...) return hex2bin(fetchkeyhex(...)); end
end

function _M.new_otp_parser(config)
	return setmetatable({
		config = config,
	}, otp_parser_mt);
end

function otp_parser:parse(otp, key)
	-- Password is any extra data before the real OTP
	local password;
	if #otp > 32 + self.config.prefix_length then
		password = otp:sub(1, #otp - (32 + self.config.prefix_length));
		otp = otp:sub(#password+1);
	end
	local prefix = otp:sub(1, self.config.prefix_length);
	local token = otp:sub(#prefix+1);
	if not key then
		key = self.config.fetch_key(prefix);
	else
		key = hex2bin(key);
	end
	if not key then return false, "no-key"; end
	key = {key:byte(1,#key)}
	local decrypted = ciphermode.decryptString(key, hex2bin(modhex2hex(token)), ciphermode.decryptCBC);
	if not decrypted then return false, "decrypt-failed"; end
	-- Extract private UID
	local uid = decrypted:sub(1,6);
	-- Build insertion counter (2 bytes)
	local use1, use2 = decrypted:sub(7,8):byte(1,2);
	local use_ctr = use1 + math.pow(2, 8)*use2;
	-- Build timestamp (3 bytes)
	local time1, time2, time3 = decrypted:sub(9,11):byte(1,3);
	local timestamp = time1 + math.pow(2,8)*time2 + math.pow(2, 16)*time3;
	-- Extract session counter (1 byte)
	local session_ctr = decrypted:sub(12, 12):byte();
	
	if crc16.hash(decrypted) ~= 0xf0b8 then
		return false, "invalid-checksum";
	end
	
	-- Return parsed fields
	return true, {
		password = password;
		public_id = prefix;
		token = token;
		private_id = bin2hex(uid);
		session_counter = session_ctr;
		use_counter = use_ctr;
		timestamp = timestamp;
	};
end

function _M.new_authenticator(config)
	local parser = _M.new_otp_parser(config);
	local function authenticate(self, otp, key, device_info, userdata)
		-- Parse OTP, get device data (from config callback)
		local ok, ret = parser:parse(otp, key);
		if not ok then return ok, ret; end
		
		if not device_info then
			device_info = config.fetch_device_info(ret);
		end
		
		if ret.use_counter < (device_info.use_counter or 0)
		or ((ret.use_counter == (device_info.use_counter or 0))
		  and (ret.session_counter <= (device_info.session_counter or 0))) then
			return false, "otp-already-used";
		end
		
		local authed, err = config.check_credentials(ret, device_info, userdata);
		if not authed then return authed, err; end
		
		device_info.use_counter = ret.use_counter;
		device_info.session_counter = ret.session_counter;
		
		config.store_device_info(device_info, userdata);
		
		return true, ret;
	end
	return { authenticate = authenticate };
end

return _M;
