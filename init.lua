local thedict , thepath = nil , nil
local script_path = function ()
   local str = debug.getinfo(2, "S").source:sub(2)
   return str:match("(.*/)")
end
local scriptpath = script_path()
local loc_name = nil
local loc = nil

local retrunifempty = function ()
	if thedict == nil or thepath == nil then
		thedict = nil
		thepath = nil
		loc = nil
		return true
	end
	return false
end

local trim = function (s,ch)
	if ch == nil then
		ch = "%s"
	end
  return (s:gsub("^" .. ch .. "*(.-)" .. ch .."*$", "%1"))
end

local get_loc_name = function (path)
	path=trim(path,"/")
	if path ~= "" then
		path=path:gsub("/","_")
	else
		path = "_"
	end
	return path
end


local getvaldict = function (key, path, dict)
	if path == nil then
		path = ""
	else
		path = path .. "_"
	end 
	return dict:get(path .. key)
end

local addcommon = function (key,val,dict)
	local succ, err = dict:safe_set(tostring(key),val)
	if not succ then
			ngx.log(ngx.ERR,"At init.lua: failed to set '" .. tostring(val) .. "' to key '" .. tostring(key) .. "' within dict: '" .. tostring(dict) .. "'. The error returned is: " .. err)
			return false
	end
	return true
end

local additem = function (key,val)
	if retrunifempty() then
		return false
	end
	if key == "" or key == nil then
		return false
	end
	key = thepath .. "_" .. key
	if val == "nil" then
		val = nil
	end
	if not addcommon(key,val,thedict) then
		return false
	end
	return true
end


local addpath = function (dict,val)
	dict = ngx.shared[dict]
	if dict ~= nil then
		--ngx.log(ngx.ERR, "dict is ok")
		val="/" .. trim(val,"/")
		local pathno = getvaldict("total_path",nil,dict)
		if pathno == nil then
			pathno = 1
		else
			for i = 1, pathno do
				local lpath = dict:get("pno" .. tostring(i))
				--ngx.say("got lpath:", tostring(lpath))
				if lpath == val then
					thedict = dict
					thepath = "pno" .. tostring(i)
					loc = val
					return true
				end
			end
			pathno = pathno + 1
		end
		--ngx.log(ngx.ERR, "path no is ",pathno)
		--ngx.log(ngx.ERR, "value is ",val)
		if not addcommon("pno" .. tostring(pathno),val,dict) then
			thedict = nil
			thepath = nil
			loc = nil
			return false
		else
			if not addcommon("total_path",pathno,dict) then
				thedict = nil
				thepath = nil
				loc = nil
				return false
			end
		end
		thedict = dict
		thepath = "pno" .. tostring(pathno)
		loc = val
		return true
	else
		ngx.log(ngx.ERR,"At init.lua: failed to set '" .. tostring(val) .. "' within dict: '" .. tostring(dict) .. "'. The dictionary was not initialized at http context")
		thedict = nil
		thepath = nil
		loc = nil
		return false
	end
end

local file_exists = function (name)
   local f = io.open(name,"r")
   local msg = nil
   if f~=nil then
    msg=f:read() 
	io.close(f) 
	return true , tonumber(msg)
   else 
	return false , msg
   end
end

local assignifempty = function (key,assign,logmsgifnil,checkkey,checkval,checkfunc)
	if retrunifempty() then
		return false
	end
	if key == nil then
		return false
	else
		key = tostring(key)
	end
	local val = getvaldict(key,thepath,thedict)
	
	if val == "" then
		val=nil
	end
	
	if assign ~= nil and val == nil then
		val = assign
	end
	
	if checkfunc == "fexist" then
		local param = getvaldict(checkkey,thepath,thedict)
		if param == checkval and not file_exists(val) then
			val = nil
		end
	end
	
	if logmsgifnil ~= nil and val == nil then
		ngx.log(ngx.ERR,logmsgifnil)
	end

	return additem(key,val)
end

local addpathcommons = function (path,location,dict)
	loc_name = get_loc_name(location)
	additem("loc_name",loc_name)
end

local validoptions = {}
validoptions['path'] = "string"
validoptions['max_ret_once'] = "number"
validoptions['total_ret'] = "number"
validoptions['total_ret_enf_sec'] = "number"
validoptions['realm'] = "string"
validoptions['secret'] = "string"
validoptions['ck_name'] = "string"
validoptions['ck_path'] = "string"
validoptions['ex_for_inactive'] = "string"
validoptions['use_ip'] = "string"
validoptions['expire_after'] = "number"
validoptions['redir_qstr'] = "string"
validoptions['method'] = "string"
validoptions['authwith'] = "string"
validoptions['err_no_on_max'] = "number"
validoptions['debug'] = "string"
validoptions['debugtoresp'] = "string"
validoptions['ck_html_file'] = "string"
validoptions['ck_html'] = "string"
validoptions['ck_text'] = "string"

local reqval = {'path','secret','authwith'}

local endpathconfig = function ()
	if retrunifempty() then
		return false
	end
	addpathcommons(thepath,loc,thedict)
	assignifempty("max_ret_once",3)
	assignifempty("total_ret",2)
	assignifempty("total_ret_enf_sec",1800)
	assignifempty("realm","=:servername:= Admins Login:( =:max_ret_once:= retries X =:total_ret:= times max in =:total_ret_enf_sec/60:= minutes )")
	assignifempty("secret", nil , 'Auth Secret is not set with "secret = mynewsecret" for path ' .. loc ..' in the config file set in ' .. scriptpath .. 'init.lua. Set it to something complicated to resume the authentication service.')
	assignifempty("ck_name",loc_name .. "_auth")
	assignifempty("ck_path","/")
	assignifempty("ex_for_inactive",true)
	assignifempty("use_ip",true)
	assignifempty("expire_after",900)
	assignifempty("redir_qstr", "checkforcookes")
	assignifempty("method", "file")
	assignifempty("authwith", nil, 'File or Commands is not given or not exist to authentice user against. Please provide a valid file path, if your method is file (default) or a command, if your method is command in the ' .. scriptpath .. 'init.lua file with "additem("authwith", "/path/to/passwd/file")".','method','file','fexist')
	assignifempty("err_no_on_max", 404)
	assignifempty("debug", false)
	assignifempty("debugtoresp", false)
	assignifempty("ck_html_file")
	assignifempty("ck_html")
	assignifempty("ck_text")
	thedict = nil
	thepath = nil
end

local assignempty = function (varr,assign)
	if varr == "" then
		varr=nil
	end
	if assign ~= nil and varr == nil then
		varr = tostring(assign)
	end
	return varr
end

local containsreqkeys = function(tbl)
	local valid = true
	for k, v in pairs( reqval ) do
		if tbl[v] == nil or tbl[v] == "" then
			valid = false
		end
	end
	return valid
end

local converttobol = function(v)
	if type(v) == "string" and (v:lower() == "yes" or v:lower() == "true")  then
		v = true
	end
	if type(v) == "string" and (v:lower() == "no" or v:lower() == "false")  then
		v = false
	end
	return v
end

local addtabletoconfig = function (tbl,dict)
	local path = tbl['path']
	tbl['path'] = nil
	if path ~= nil then
		addpath(dict,path)
		for k, v in pairs( tbl ) do
			if v ~= nil and v ~= "" then
				additem(k,converttobol(v))
			end	
		end
		endpathconfig()
	else
		return false
	end
	return true
end
local flusheddict = {}
local flushdict = function (dict)
	if flusheddict[dict] == nil then
		local dicttoflush = ngx.shared[dict]
		dicttoflush:flush_all()
		dicttoflush:flush_expired()
		flusheddict[dict] = "flushed"
	end
end

if file_exists(scriptpath .. "init.conf") then
	for line in io.lines(scriptpath .. "init.conf") do
		line = trim(line)
		if line ~= "" and line:sub(1,1) ~= "#" then
			local divider = line:find(" ")
			if divider ~= nil then
				local dict = assignempty(trim(line:sub(1,divider-1)))
				if dict ~= nil then
					flushdict(dict)
				end
				local conffile = assignempty(trim(line:sub(divider+1)))
				if conffile:sub(1,1) ~= "/" then
					conffile = scriptpath .. conffile
				end
				if dict ~= nil and conffile ~= nil and file_exists(conffile) then
					local lastpath = nil
					local temptable = {}
					for cline in io.lines(conffile) do
						cline = trim(cline)
						if cline ~= "" and cline:sub(1,1) ~= "#" then
							local cdivider = cline:find("=")
							if cdivider ~= nil then
								local key = assignempty(trim(cline:sub(1,cdivider-1)))
								local val = assignempty(trim(cline:sub(cdivider+1)))
								if key ~= nil and validoptions[key] ~= nil and val ~= nil then
									val = trim(val,"'")
									val = trim(val,'"')
									if validoptions[key] == "string" and tostring(val) ~= nil then
										if key == "path" then
											if next(temptable) ~= nil then
												if containsreqkeys(temptable) then
													addtabletoconfig(temptable,dict)
													temptable = {}
												else
													temptable = {}
													ngx.log(ngx.ERR,"All required values for path: ",lastpath, " in conf file: ", conffile, " not provided or empty. The required values are: ", to_string(reqval))
												end
											end
											lastpath = val
										end
										if lastpath == nil then
											ngx.log(ngx.ERR,"config file: " .. conffile .. " contains error, path key not found as the first entry")
											break
										end
										temptable[key] = tostring(val)
									elseif validoptions[key] == "number" then
										if lastpath == nil then
											ngx.log(ngx.ERR,"config file: " .. conffile .. " contains error, path key not found as the first entry")
											break
										end
										val = tonumber(val)
										if val == nil then
											ngx.log(ngx.ERR,"the key: ", key ," contains invalid value, but requires number for path: ",lastpath," in config file: " .. conffile, ". Using defaults, if permitted." )
										else
											temptable[key] = val
										end
									end
								end
							end
						end
					end
					if next(temptable) ~= nil then
						if containsreqkeys(temptable) then
							addtabletoconfig(temptable,dict)
							temptable = {}
						else
							temptable = {}
							ngx.log(ngx.ERR,"All required values for path: ",lastpath, " in conf file: ", conffile, " not provided or empty. The required values are: ", to_string(reqval))
						end
					end
				end
			end
		end
	end
end



