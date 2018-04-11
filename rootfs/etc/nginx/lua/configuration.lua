-- this is the Lua representation of Configuration struct in internal/ingress/types.go
local first_config_load = ngx.shared.first_config_load
local configuration_data = ngx.shared.configuration_data

local _M = {}

local function get_uuid_code()
  local urandom = assert(io.open('/dev/urandom','rb'))
  local a, b, c, d = urandom:read(4):byte(1,4)
  urandom:close()

  local seed = a*0x1000000 + b*0x10000 + c *0x100 + d
  math.randomseed(seed)

  local random = math.random
  local template ='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'

  return string.gsub(template, '[xy]', function (fc)
    local v = (fc == 'x') and random(0, 0xf) or random(8, 0xb)
      return string.format('%x', v)
  end)
end

function _M.get_config_data()
  return configuration_data:get("config")
end

function _M.get_config_check_code()
  return configuration_data:get("config_check_code")
end

function _M.call()
  if ngx.var.request_method ~= "POST" and ngx.var.request_method ~= "GET" then
    ngx.status = ngx.HTTP_BAD_REQUEST
    ngx.print("Only POST and GET requests are allowed!")
    return
  end

  if ngx.var.request_uri ~= "/configuration" then
    ngx.status = ngx.HTTP_NOT_FOUND
    ngx.print("Not found!")
    return
  end

  if ngx.var.request_method == "GET" then
    ngx.status = ngx.HTTP_OK
    ngx.print(_M.get_config_data())
    return
  end

  ngx.req.read_body()

  local success, err = configuration_data:set("config", ngx.req.get_body_data())
  if not success then
    ngx.log(ngx.ERR, "error while saving configuration: " .. tostring(err))
    ngx.status = ngx.HTTP_BAD_REQUEST
    return
  end

  local config_check_code = get_uuid_code()
  ngx.log(ngx.INFO, "Configuration Check Code: " .. tostring(config_check_code))

  local check_success, check_err = configuration_data:set("config_check_code", config_check_code)
  if not check_success then
    ngx.log(ngx.ERR, "error while saving configuration check code: " .. tostring(check_err))
    ngx.status = ngx.HTTP_BAD_REQUEST
    return
  end

  local fcl = first_config_load:get("ok")
  if fcl ~= nil then
    first_config_load:set("ok", true)
  end
  if fcl ~= true then
    first_config_load:set("ok", true)
  end

  ngx.status = ngx.HTTP_CREATED
end

function _M.check()
  local fcl = first_config_load:get("ok")
  if fcl == nil then
    ngx.log(ngx.INFO, "Healty check Code: 503")
    ngx.status = 503
  elseif fcl ~= true then
    ngx.log(ngx.INFO, "Healty check Code: 503")
    ngx.status = 503
  else
    ngx.log(ngx.INFO, "Healty check Code: 200")
    ngx.status = 200
  end
end

return _M
