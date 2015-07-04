local ngx_request_uri = ngx.var.request_uri
local debugresponse = false
local debugmode = false
local filetolog = ""
local logmode = "a+"

local trim = function (s,ch)
	if ch == nil then
		ch = "%s"
	end
  return (s:gsub("^" .. ch .. "*(.-)" .. ch .."*$", "%1"))
end

local assignifempty = function (varr,assign)
	if varr == "" then
		varr=nil
	end
	if assign ~= nil and varr == nil then
		varr = tostring(assign)
	end
	return varr
end

local script_path = function ()
   local str = debug.getinfo(2, "S").source:sub(2)
   return str:match("(.*/)")
end

local command = function (cmd,no_lf)
    local f = io.popen(cmd..' 2>&1; echo "-retcode:$?"' ,'r')
    local l = f:read '*a'
    f:close()
    local i1,i2,ret = l:find('%-retcode:(%d+)\n$')
    if no_lf and i1 > 1 then i1 = i1 - 1 end
    l = l:sub(1,i1-1)
    return trim(l),tonumber(ret)
end

local timeprinted = nil
local logtofile = function (loglife, mode, ...)
	if debugmode then
		local retval = false
		local valtable = {}
		for key,value in pairs({...}) do 
			table.insert(valtable, tostring(value))
		end
		if next(valtable) == nil then
			ngx.log(ngx.ERR, "Logging table : valtable  has failed, as it is found nil.")
			return retval
		end
		local file , errmsg = io.open(loglife, mode)
		if file ~= nil then
			if timeprinted == nil then
				retval = file:write("\n********************************\nThe process started at: ",ngx.localtime()," :\n",unpack(valtable))
				timeprinted="yes"
			else
				retval = file:write(unpack(valtable))
			end
			file:close()
		else
				ngx.log(ngx.ERR, "Logging to file : " .. loglife .. " has failed.", "Error msg: ", errmsg)
		end
		return retval
	else
		return true
	end
end

local readAll = function (file)
    local f = io.open(file, "rb")
    local content = f:read("*all")
    f:close()
    return content
end

local getvaldict = function (key, pno, dict)
	if pno == nil then
		pno = ""
	else
		pno = pno .. "_"
	end 
	return dict:get(pno .. key)
end

local setvaldict = function (key, pno, val, dict, expire)
	local succ, err = nil , nil
	if pno == nil then
		pno = ""
	else
		pno = pno .. "_"
	end 
	if expire ~= nil then
		succ, err = dict:set(pno .. tostring(key),val,expire)
    else
		succ, err = dict:set(pno .. tostring(key),val)
    end
	if not succ then
		ngx.log(ngx.ERR,"At access.lua: failed to set '" .. tostring(val) .. "' to key '" .. pno .. tostring(key) .. "' within dict: '" .. tostring(dict) .. "'. The error returned is: " .. err)
		return false
	end
	return true
end

local configpath = function (requri,dict,prelog)
	local path = nil
	local pathno = nil
	local requriwslash = nil
	if requri ~= "/" then
		requriwslash = requri .. "/"
	end
	local totalpath = dict:get("total_path")
	prelog = "\n====================\ntotal_path = " .. totalpath
	for i = 1, totalpath do
		local lpath = dict:get("pno" .. tostring(i))
		prelog = prelog .. "\npno" .. tostring(i) .. " : " .. tostring(lpath)
		if requri:find(lpath) == 1 or (requriwslash ~= nil and requriwslash:find(lpath) == 1) then
			if path then
				if lpath:len() > path:len() then
					path = lpath
					pathno = i
				end
			else
				path = lpath
				pathno = i
			end
		end
	end
	
	if pathno ~= nil then
		pathno = "pno" .. pathno
	end
	
	if path == "/" then
		local is_args=string.find(ngx_request_uri,"?")
		if is_args then
			path = string.sub(ngx_request_uri,1,is_args-1)
		else
			path = ngx_request_uri
		end
	end

	prelog = prelog .. "\nwe selected :" .. tostring(pathno) .. ": for request_uri=" .. ngx_request_uri .. " and path = " .. path
	logtofile(filetolog,logmode,prelog)
	return pathno,path,prelog
end

local breakonnil = function (val,errmsg,errno)
	if val == nil then
		ngx.log(ngx.ERR,errmsg)
		if errno == nil then
			errno = ngx.HTTP_SERVICE_UNAVAILABLE
		end
		return ngx.exit(ngx.errno)
	end
	return val
end

local getconfigkeys = function (keynm, config, nobreak)
	if nobreak == nil then
		local errmsg = " : value can't retrieve for path: " .. config['path']
		config[keynm] = breakonnil(getvaldict(keynm,config['pathno'],config['dict']),keynm .. errmsg )
		logtofile(filetolog,logmode,"\n",keynm," = ",config[keynm], " and type = ", type(config[keynm]))
		return config
	else
		config[keynm] = assignifempty(getvaldict(keynm,config['pathno'],config['dict']))
		logtofile(filetolog,logmode,"\n",keynm," = ",config[keynm], " and type = ", type(config[keynm]))
		return config
	end
end

local ngx_server_name = ngx.var.server_name

local getconfig = function ()
	local config = {}
	local prelog = "\n====================\n" .. "The configs we got: "
	config['dict_name'] = breakonnil(assignifempty(ngx.var.lua_auth_dict_name),'Auth Dictonary Name is not set with "set $lua_auth_dict_nam xxxxxxxxxxxx;" in server context. Set it to a configuration dictionary name as per init.lua file to resume the authentication service.')
	prelog = prelog .. "\ndict_name = " .. config['dict_name']
	config['dict'] = breakonnil(ngx.shared[config['dict_name']],"We can't reference the dictionary named: " .. config['dict_name'])
	config['pathno'] , config['path'], prelog = configpath(ngx_request_uri,config['dict'],prelog)
	breakonnil(config['pathno'],'We cannot find any defined path as for the request ' .. ngx_request_uri .. '. Add a appropiate path in init.lua file to resume the authentication service.')
	
	if debugmode then
		prelog = nil
	end
	
	config=getconfigkeys('debug',config)
	if config['debug'] == true then
		debugmode = true
	end
	
	if prelog ~= nil then
		logtofile(filetolog,logmode,prelog)
	end
	
	config=getconfigkeys('debugtoresp',config)
	if config['debugtoresp'] == true then
		debugresponse = true
	end
	
	config=getconfigkeys('secret',config)
	config=getconfigkeys('method',config)
	config=getconfigkeys('authwith',config)
	config=getconfigkeys('err_no_on_max',config)
	config=getconfigkeys('loc_name',config)
	config=getconfigkeys('max_ret_once',config)
	config=getconfigkeys('total_ret',config)
	config=getconfigkeys('total_ret_enf_sec',config)
	config=getconfigkeys('realm',config)
	config=getconfigkeys('ck_name',config)
	config=getconfigkeys('ck_path',config)
	config=getconfigkeys('ex_for_inactive',config)
	config=getconfigkeys('use_ip',config)
	config=getconfigkeys('expire_after',config)
	config=getconfigkeys('redir_qstr',config)
	config=getconfigkeys('ck_html_file',config,true)
	config=getconfigkeys('ck_html',config,true)
	config=getconfigkeys('ck_text',config,true)
	
	config['realm'] = config['realm']:gsub("=:servername:=",ngx_server_name)
	config['realm'] = config['realm']:gsub("=:max_ret_once:=",config['max_ret_once'])
	config['realm'] = config['realm']:gsub("=:total_ret:=",config['total_ret'])
	config['realm'] = config['realm']:gsub("=:total_ret_enf_sec/60:=",tostring(config['total_ret_enf_sec']/60))
	logtofile(filetolog,logmode,"\n final realm = ",config['realm'])
	return config
end

local scriptpath = script_path()
filetolog = scriptpath .. "auth.out.log"
local auth_config = getconfig()
local temp_dict_name = breakonnil(assignifempty(ngx.var.lua_temp_dict_name),'Auth Temporary Dictonary Name is not set with "set $lua_temp_dict_name xxxxxxxxxxxx;" in server context. Set it to resume the authentication service.')
local temp_dict = breakonnil(ngx.shared[temp_dict_name],"We can't reference the dictionary named: " .. temp_dict_name)

local auth_cookie = assignifempty(ngx.var["cookie_" .. auth_config['ck_name']])
local auth_check_redir_value = assignifempty(ngx.var["arg_" .. auth_config['redir_qstr']])
local auth_check_redir_path = auth_config['path'] .. "?" .. auth_config['redir_qstr']

local redirfinalval = auth_check_redir_value
local checkexpireval = nil
if redirfinalval ~= nil then
	checkexpireval = assignifempty(ngx.var.arg_tm)
end 
local checkexpire = ngx.time() + 5
if checkexpireval ~= nil and tonumber(checkexpireval) == nil then
	checkexpireval = nil
end

local headers = ngx.req.get_headers();
local cookie = auth_cookie
local retries = 0
local retries_total = 0
local usercookieid = nil
local ngx_remote_addr = ngx.var.remote_addr
local sendauthlog = false
local userchecked = false
local userfound = nil

logtofile(filetolog,logmode,"\n====================\n","Requested uri: ",ngx_request_uri);
logtofile(filetolog,logmode,"\n====================\n","The auth cookie we got: ",cookie)

local setauthtoken = function ()
	if auth_config['use_ip'] then
		return setvaldict(usercookieid,auth_config['pathno'] .. "_authed",userfound .. ":" .. ngx_remote_addr,temp_dict,auth_config['expire_after'])
	else
		return setvaldict(usercookieid,auth_config['pathno'] .. "_authed",userfound,temp_dict,auth_config['expire_after'])
	end
end

local getauthtoken = function ()
return assignifempty(getvaldict(usercookieid,auth_config['pathno'] .. "_authed",temp_dict))
end

local set_retries = function ()
	if usercookieid == nil then
		return false
	end
	local nextval = nil
	local retval = true
	local retriesval = assignifempty(getvaldict(usercookieid,auth_config['pathno'],temp_dict))
	if retriesval ~= nil then
		local divider = retriesval:find(':')
		if divider ~= nil then
			retries = tonumber(retriesval:sub(1,divider-1))
			retries_total = tonumber(retriesval:sub(divider+1))
			if retries_total > auth_config['total_ret'] then
				retries = "max"
				nextval = "0:" .. tostring(auth_config['total_ret']+1)
			elseif retries >= auth_config['max_ret_once'] then
				retries = "max"
				nextval = "0:" .. tostring(retries_total+1)
			else
				nextval = tostring(retries+1) .. ":".. tostring(retries_total)
			end
		end
	else
		nextval = "1:1"
	end
	if nextval ~= nil then
		setvaldict(usercookieid,auth_config['pathno'],nextval,temp_dict,auth_config['total_ret_enf_sec'])
	end
	return true
end
local clear_retries = function ()
	setvaldict(usercookieid,auth_config['pathno'],nil,temp_dict,1)
end

local check_retries = function ()
	logtofile(filetolog,logmode,"\n====================\n","Retries no: ", retries, " retries_total: ", retries_total)
	if retries == 0 then
		return true
	end
	return false
end

local buildcmd = function ( ... )
	local valstr = nil
	for key,value in pairs({...}) do
		if valstr == nil then
			valstr = '"' .. tostring(value) .. '"'
		else
			valstr = valstr .. ' "' .. tostring(value) .. '"'
		end
	end
	
	if valstr ~= nil then
		return valstr
	end
	return false
end

local get_user = function (ckchk)

	if userchecked == false then
		userchecked = true
	else
		return userfound
	end

	if ckchk and check_retries() then
		return
	end
	
	local header =  headers['Authorization']
	if header == nil or header:find(" ") == nil then
		return
	end
   
	local divider = header:find(' ')
	if header:sub(0, divider-1) ~= 'Basic' then
		return
	end
   
	local auth = ngx.decode_base64(header:sub(divider+1))
	if auth == nil or auth:find(':') == nil then
		if sendauthlog == false then
			ngx.log(ngx.ERR,"no user/password was provided for basic authentication")
			sendauthlog = true
		end
		return
	end
	
	divider = auth:find(':')
	local user = auth:sub(0, divider-1)
	local pass = auth:sub(divider+1)
	
	if user == nil or user == "" or pass == nil or pass == "" then
		if sendauthlog == false then
			ngx.log(ngx.ERR,"no user/password was provided for basic authentication")
			sendauthlog = true
		end
		return
	end
	
	if auth_config['method'] == "file" then
		local usrcred = nil
		for line in io.lines(auth_config['authwith']) do
			local res = line:match('^' .. user .. ':.-$')
			if res then
				usrcred = res
				break
			end
		end
		if usrcred ~= nil and usrcred ~= "" then
			local thecryptpass = usrcred:sub(user:len()+2)
			local salt = thecryptpass:sub(1,2)
			local getvpass,excode = command("openssl passwd -salt " .. salt .. " -noverify " .. pass)
			if excode == 0 and thecryptpass == getvpass then
				userfound = user
				return user
			else
				if excode ~= 0 then
					if sendauthlog == false then
						ngx.log(ngx.ERR,getvpass)
						sendauthlog = true
					end
				else
					if sendauthlog == false then
						ngx.log(ngx.ERR,"user \"" .. user .. "\": password mismatch")
						sendauthlog = true
					end
				end
			end
		else
			if sendauthlog == false then
				ngx.log(ngx.ERR,"user \"" .. user .. "\" was not found in " .. auth_config['authwith'])
				sendauthlog = true
			end
		end
	end
	
	if auth_config['method'] == "cmd" then
		local params = buildcmd(user,pass,ngx.encode_base64(usercookieid),auth_config['path'],ngx_server_name,ngx_remote_addr,ngx_request_uri)
		if params == false then
			return
		end
		logtofile(filetolog,logmode,"\n====================\n","seding this command : ", auth_config['authwith'] .. ' ' .. params)
		local getvpass,excode = command(auth_config['authwith'] .. ' ' .. params)
		if excode == 0 and pass == getvpass then
			userfound = user
			return user
		else
			if sendauthlog == false then
				ngx.log(ngx.ERR,getvpass)
				sendauthlog = true
			end
		end
	end
   
	return
end

local isvalidcookieid = function ()
	local expires_after = 31536000
	local divider = cookie:find(":")
	local hmac = ngx.decode_base64(cookie:sub(divider+1))
	local timestamp = cookie:sub(1, divider-1)
	local validtill = tonumber(timestamp) + expires_after
	local secret = nil
	local tokenstr = nil
	if auth_config['use_ip'] then
		secret = auth_config['secret'] .. tostring(timestamp) .. auth_config['secret'] .. tostring(validtill) .. tostring(ngx_remote_addr) .. tostring(headers['user-agent'])
		tokenstr = tostring(ngx_remote_addr) .. tostring(validtill) .. tostring(headers['user-agent']) .. auth_config['secret']
	else
		secret = auth_config['secret'] .. tostring(timestamp) .. auth_config['secret'] .. tostring(validtill) .. tostring(headers['user-agent'])
		tokenstr = tostring(validtill) .. tostring(headers['user-agent']) .. auth_config['secret']

	end
	logtofile(filetolog,logmode,"\n====================\n","The hmac we get : ",hmac, " :it should: ", ngx.hmac_sha1(secret, tokenstr))
	if ngx.hmac_sha1(secret, tokenstr) == hmac and validtill >= ngx.time() then
		if hmac ~= nil then
			usercookieid = hmac
		end
		return true
	else
		return false
	end
end

local set_auth_cookie = function ()
	local expires_after = 31536000
	local timestamp = ngx.time()
	local validtill = timestamp + expires_after
	local secret = nil
	local tokenstr = nil
	if auth_config['use_ip'] then
		secret = auth_config['secret'] .. tostring(timestamp) .. auth_config['secret'] .. tostring(validtill) .. tostring(ngx_remote_addr) .. tostring(headers['user-agent'])
		tokenstr = tostring(ngx_remote_addr) .. tostring(validtill) .. tostring(headers['user-agent']) .. auth_config['secret']
	else
		secret = auth_config['secret'] .. tostring(timestamp) .. auth_config['secret'] .. tostring(validtill) .. tostring(headers['user-agent'])
		tokenstr = tostring(validtill) .. tostring(headers['user-agent']) .. auth_config['secret']

	end
		
	local token = timestamp .. ":" .. ngx.encode_base64(ngx.hmac_sha1(
       secret,
       tokenstr))
    local cookie = auth_config['ck_name'] .. "=" .. token .. "; "
	cookie = cookie .. "Path=" .. auth_config['ck_path'] .. "; Domain=" .. ngx_server_name .. "; "
	cookie = cookie .. "Expires=" .. ngx.cookie_time(validtill) .. "; "
	cookie = cookie .. "; Max-Age=" .. expires_after .. "; HttpOnly"
	return cookie,token
end

local ask_for_auth = function ()
ngx.header.www_authenticate = 'Basic realm="' .. auth_config['realm'] .. '"'
return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local processslogin = function ()
	local user = get_user(true)
	logtofile(filetolog,logmode,"\n====================\n","The user we get : ",user)
	if user then
	   ngx.log(ngx.NOTICE, 'Authenticated : ' .. user)
	   setauthtoken()
	   clear_retries()
	   logtofile(filetolog,logmode,"\n====================\n","User : ",user," Authenticated")
	   return ngx.exit(ngx.OK)
	else
	   if tostring(retries) == "max" then
			logtofile(filetolog,logmode,"\n====================\n","Client reached max retries")
			return ngx.exit(auth_config['err_no_on_max'])
	   else
			logtofile(filetolog,logmode,"\n====================\n","Client is asked for authentication")
			ask_for_auth()
	   end
	end
	
end

if cookie ~= nil and cookie:find(":") ~= nil then
	if redirfinalval ~= nil then
		ngx.redirect(ngx.unescape_uri(redirfinalval))
	end

	local tokenok = false
	local token = nil
	local clip = nil
	local cluser = nil
	if isvalidcookieid() then
		token = getauthtoken()
		if token ~= nil then
			if auth_config['use_ip'] then
				local divider = token:find(":")
				if divider ~= nil then
					cluser = token:sub(1,divider-1)
					clip = token:sub(divider+1)
				end
			else
				cluser = token
			end
		end
	end
	if cluser ~= nil and cluser == get_user(false) then
		if auth_config['use_ip'] and  clip == ngx_remote_addr then
			tokenok = true
		else
			tokenok = true
		end
	end
	logtofile(filetolog,logmode,"\nInto auth check : ", "usercookieid = ",usercookieid)
	if tokenok then
	    setauthtoken()
		if debugresponse then
			ngx.header.content_type = "text/plain"
			ngx.say("Auth cookie is valid", "\nTime now: ",ngx.cookie_time(ngx.time()),"\nValid till: ",ngx.cookie_time(ngx.time()+auth_config['expire_after']),"\nThe headers from clients are:","\n====================")
			for k, v in pairs( headers ) do
			   ngx.say(k ," : " ,v)
			end
		end		
		if debugmode then
			logtofile(filetolog,logmode,"\n====================\n","Auth token is valid","\nTime now: ",ngx.cookie_time(ngx.time()),"\nValid till: ",ngx.cookie_time(ngx.time()+auth_config['expire_after']), "\nThe headers from clients are:","\n====================\n")
			for k, v in pairs( headers ) do
			   logtofile(filetolog,logmode,"\n",k ," : " ,v)
			end
		end
	   return ngx.exit(ngx.OK)		
	else
		if debugmode then
			logtofile(filetolog,logmode,"\n====================\n","Auth token is NOT valid", "\nThe headers from clients are:","\n====================\n")
			for k, v in pairs( headers ) do
			   logtofile(filetolog,logmode,"\n",k ," : " ,v)
			end	
		end
		
		if set_retries() then
			processslogin()
		else
			return ngx.exit(ngx.HTTP_FORBIDDEN)
		end
	end
else

	local redirtocheck = ""
	
	logtofile(filetolog,logmode,"\nThe value of cookie check: ", "redirfinalval = ",redirfinalval)
	
	if checkexpireval ~= nil and redirfinalval ~= nil and ngx_request_uri == auth_check_redir_path .. "=" .. redirfinalval .. "&tm=" .. checkexpireval then
		redirtocheck = auth_check_redir_path .. "=" .. redirfinalval .. "&tm=" .. checkexpire
	else
		redirtocheck = auth_check_redir_path .. "=" .. ngx.escape_uri(ngx_request_uri) .. "&tm=" .. checkexpire
	end
	
	
	if redirfinalval ~= nil and checkexpireval ~= nil and tonumber(checkexpireval) >= ngx.time()  and ngx_request_uri == auth_check_redir_path .. "=" .. redirfinalval .. "&tm=" .. checkexpireval then
		ngx.log(ngx.NOTICE, 'user doesn\'t have cookie enabled, denying authentication.')
		if auth_config['ck_html_file'] ~= nil then
			ngx.header.content_type = 'text/html'
			ngx.print(readAll(auth_config['ck_html_file']))
		elseif auth_config['ck_html'] ~= nil then
			ngx.header.content_type = 'text/html'
			ngx.say(auth_config['ck_html'])
		elseif auth_config['ck_text'] ~= nil then
			ngx.header.content_type = 'text/plain'
			ngx.say(auth_config['ck_text'])
		else
			ngx.header.content_type = 'text/html'
			ngx.say('<html><head><meta name="viewport" content="width=device-width, initial-scale=1"></head><body><p>Cookies is disabled in your http client (e.g. Browser) or have some problems accepting cookies. Please enable cookies or rectify any such problems to use this section of this site.</p><p>If you don\'t know how, learn more about it for the following internet browsers:&nbsp;<a href="https://discussions.apple.com/thread/1506528" target="_blank" >Safari</a>, <a href="https://support.google.com/accounts/answer/61416?hl=en" target="_blank" >Chrome</a>, <a href="http://windows.microsoft.com/en-gb/internet-explorer/delete-manage-cookies" target="_blank">Internet Explorer</a>, or <a href="https://support.mozilla.org/en-US/kb/enable-and-disable-cookies-website-preferences" target="_blank" >Firefox</a>. If you are unsure about what browser you are using, please click on&nbsp;<a href="https://whatbrowser.org/" target="_blank" >this link</a>. What browser you are using will be listed on the left-hand side of the screen. Then search in google with this term \'How to enable cookies in {your browser name}\'</p><p>After enabling cookies, just refresh this page to continue.</p></body></html>')
		end
		
		return ngx.exit(ngx.HTTP_OK)
	else
		local startauthcookie = (set_auth_cookie())
		ngx.header['Set-Cookie'] = startauthcookie
		return ngx.redirect(redirtocheck)
	end
	
end
