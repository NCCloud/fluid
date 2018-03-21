local ngx_balancer = require("ngx.balancer")
local ssl = require "ngx.ssl"
local json = require("cjson")
local configuration = require("configuration")
local util = require("util")
local lrucache = require("resty.lrucache")
local resty_lock = require("resty.lock")

-- measured in seconds
-- for an Nginx worker to pick up the new list of configs
-- it will take <the delay until controller POSTed the backend object to the Nginx endpoint> + CONFIG_SYNC_INTERVAL
local CONFIG_SYNC_INTERVAL = 1

local ROUND_ROBIN_LOCK_KEY = "round_robin"

local round_robin_state = ngx.shared.round_robin_state

local _M = {}

local round_robin_lock = resty_lock:new("locks", {timeout = 0, exptime = 0.1})

local servers, err = lrucache.new(1024)
if not servers then
  return error("failed to create the cache for servers: " .. (err or "unknown"))
end

local backends, err = lrucache.new(1024)
if not backends then
  return error("failed to create the cache for backends: " .. (err or "unknown"))
end

local function sync_server(server)
  servers:set(server.hostname, server)

  ngx.log(ngx.INFO, "server syncronization completed for: " .. server.hostname)
end

local function sync_backend(backend)
  backends:set(backend.name, backend)

  -- also reset the respective balancer state since backend has changed
  round_robin_state:delete(backend.name)

  ngx.log(ngx.INFO, "backend syncronization completed for: " .. backend.name)
end

local function sync_config()
  local config_data = configuration.get_config_data()
  if not config_data then
    return
  end

  local ok, new_config = pcall(json.decode, config_data)
  if not ok then
    ngx.log(ngx.ERR,  "could not parse config data: " .. tostring(new_config))
    return
  end

  local new_servers = new_config.servers
  for _, new_server in pairs(new_servers) do
    local server = servers:get(new_server.hostname)
    local server_changed = true

    if server then
      server_changed = not util.deep_compare(server, new_server)
    end

    if server_changed then
      sync_server(new_server)
    end
  end

  local new_backends = new_config.backends
  for _, new_backend in pairs(new_backends) do
    local backend = backends:get(new_backend.name)
    local backend_changed = true

    if backend then
      backend_changed = not util.deep_compare(backend, new_backend)
    end

    if backend_changed then
      sync_backend(new_backend)
    end
  end
end

function _M.init_worker()
  _, err = ngx.timer.every(CONFIG_SYNC_INTERVAL, sync_config)
  if err then
    ngx.log(ngx.ERR, "error when setting up timer.every for sync_config: " .. tostring(err))
  end
end

function _M.rewrite()
  local http_host = ngx.var.http_host
  local request_uri = ngx.var.request_uri
  ngx.log(ngx.INFO, "SSL Redirect http_host: " ..  tostring(http_host) .. " request_uri: " ..  tostring(request_uri))
  local server = servers:get(http_host)
  if (server == nil) then
    server = servers:get("_")
    if (server == nil) then
      ngx.status = 503
      ngx.exit(ngx.status)
    end
  end
  
  local scheme = ngx.var.scheme
  local redirect_to_https = ngx.var.redirect_to_https
  ngx.log(ngx.INFO, "SSL Redirect scheme: " ..  tostring(scheme) .. " redirect_to_https: " ..  tostring(redirect_to_https))
  local location
  local hit_length = 0
  for k, v in pairs(server.locations) do
    local path = v.path
    ngx.log(ngx.INFO, "Checking request: " ..  tostring(request_uri) .. " against path: " .. tostring(path))
    local path_length = string.len(v.path)
    if string.sub(request_uri, 1, path_length) == path then
      ngx.log(ngx.INFO, "Path MATCH: " .. tostring(path))
      if path_length > hit_length then
        hit_length = path_length
        location = server.locations[k]
      end
    end
  end
  if (location == nil) then
    ngx.status = 404
    ngx.exit(ngx.status)
  end

  if scheme == 'http' then
    ngx.log(ngx.INFO, "SSL Redirect configs: forceSSLRedirect=" ..  tostring(location.rewrite.forceSSLRedirect))
    ngx.log(ngx.INFO, "SSL Redirect configs: sslCertificateReal=" ..  tostring(server.sslCertificateReal))
    ngx.log(ngx.INFO, "SSL Redirect configs: sslRedirect=" ..  tostring(location.rewrite.sslRedirect))
    if location.rewrite.forceSSLRedirect or (server.sslCertificateReal ~= "" and location.rewrite.sslRedirect) then
      if redirect_to_https == "1" then
        ngx.log(ngx.INFO, "SSL Redirect(" .. http_host .. "): " .. request_uri)
        return ngx.redirect("https://" .. http_host .. request_uri, 301)
      end
    end
  end
end

function _M.ssl()
  local http_host = ngx.var.http_host
  ngx.log(ngx.INFO, "SSL handshake http_host: " ..  tostring(http_host))
  local server = servers:get(http_host)
  if (server == nil) then
    server = servers:get("_")
    if (server == nil) then
      ngx.status = 503
      ngx.exit(ngx.status)
    end
  end
  
  if server.sslCertificateReal ~= "" then
    local ok, err = ssl.clear_certs()
    if not ok then
      ngx.log(ngx.ERR, "SSL ["..http_host.."]: failed to clear fallback certificates")
      return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    
    local cert_key_data = server.sslCertificateReal
    if cert_key_data == nil then
      ngx.log(ngx.ERR, "SSL certificate not found in memory")
      return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    local der_cert_chain, err = ssl.cert_pem_to_der(cert_key_data)
    if not der_cert_chain then
      ngx.log(ngx.ERR, "failed to convert certificate chain ", "from PEM to DER: ", err)
      return ngx.exit(ngx.ERROR)
    end
    local ok, err = ssl.set_der_cert(der_cert_chain)
    if not ok then
      ngx.log(ngx.ERR, "failed to set DER cert: ", err)
      return ngx.exit(ngx.ERROR)
    end
    local der_pkey, err = ssl.priv_key_pem_to_der(cert_key_data)
    if not der_pkey then
      ngx.log(ngx.ERR, "failed to convert private key ", "from PEM to DER: ", err)
      return ngx.exit(ngx.ERROR)
    end
    local ok, err = ssl.set_der_priv_key(der_pkey)
    if not ok then
      ngx.log(ngx.ERR, "failed to set DER private key: ", err)
      return ngx.exit(ngx.ERROR)
    end
  else
    ngx.status = 405
    ngx.exit(ngx.status)
  end
end

function _M.balance()
  ngx_balancer.set_more_tries(1)

  local backend_name = ngx.var.proxy_upstream_name
  local backend = backends:get(backend_name)
  -- lb_alg field does not exist for ingress.Backend struct for now, so lb_alg
  -- will always be round_robin
  local lb_alg = backend.lb_alg or "round_robin"

  if lb_alg == "ip_hash" then
    -- TODO(elvinefendi) implement me
    return backend.endpoints[0].address, backend.endpoints[0].port
  end

  -- Round-Robin
  round_robin_lock:lock(backend_name .. ROUND_ROBIN_LOCK_KEY)
  local last_index = round_robin_state:get(backend_name)
  local index, endpoint = next(backend.endpoints, last_index)
  if not index then
    index = 1
    endpoint = backend.endpoints[index]
  end
  round_robin_state:set(backend_name, index)
  round_robin_lock:unlock(backend_name .. ROUND_ROBIN_LOCK_KEY)

  local host = endpoint.address
  local port = endpoint.port

  local ok
  ok, err = ngx_balancer.set_current_peer(host, port)
  if ok then
    ngx.log(ngx.INFO, "current peer is set to " .. host .. ":" .. port)
  else
    ngx.log(ngx.ERR, "error while setting current upstream peer to: " .. tostring(err))
  end
end

return _M
