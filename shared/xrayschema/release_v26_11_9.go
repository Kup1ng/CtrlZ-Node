package xrayschema

// The allow-list of Xray v26.11.9 (2026-11-09), written from the structs of
// infra/conf at that tag and from xtls.github.io the same day. It lists the keys
// an outbound can use as a client; the server-side keys of the same structs
// (fallbacks, serverNames, privateKey, ...) are left out on purpose, so a pasted
// server config stops at a warning instead of being sent to a node.
//
// Reading guide for the next release: copy this file, change the keys that moved,
// register it in tables.go, keep this one. A node may stay on any release that was
// ever shipped (7.2), so no table is ever deleted.

func outbound() *node {
	protocols := map[string]*node{
		"vless":       vlessSettings(),
		"vmess":       vmessSettings(),
		"trojan":      trojanSettings(),
		"shadowsocks": shadowsocksSettings(),
		"socks":       socksSettings(),
		"http":        httpSettings(),
		"hysteria":    hysteriaSettings(),
		"wireguard":   wireguardSettings(),
		"freedom":     freedomSettings(),
	}
	return obj(
		f("protocol", enumOf(false, "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "hysteria", "wireguard", "freedom")),
		f("tag", str()),
		f("settings", raw()),
		f("streamSettings", streamSettings()),
		f("mux", obj(
			f("enabled", boolean()), f("concurrency", num()), f("xudpConcurrency", num()), f("xudpProxyUDP443", str()),
		)),
		f("targetStrategy", str()),
	).withVariant("protocol", "settings", protocols)
}

// ---- protocols ------------------------------------------------------------------

// vlessSettings leaves out testpre and testseed on purpose. testpre starts that many
// pre-dial goroutines in the one Xray process every location of the node shares, and
// none of them ends with the generation, so it is on the always-rejected list
// (globalRejected): a warning would pass with accept_unknown. testseed only tunes
// Vision padding and stops at a warning like any key the table does not hold.
func vlessSettings() *node {
	user := obj(f("id", str()), f("flow", str()), f("encryption", str()), f("level", num()), f("email", str()),
		f("seed", str()))
	return obj(
		f("address", str()), f("port", num()), f("level", num()), f("email", str()), f("id", str()),
		f("flow", str()), f("seed", str()), f("encryption", str()),
		f("vnext", arr(obj(f("address", str()), f("port", num()), f("users", arr(user))))),
	)
}

func vmessSettings() *node {
	user := obj(f("id", str()), f("security", str()), f("experiments", str()), f("level", num()), f("email", str()))
	return obj(
		f("address", str()), f("port", num()), f("level", num()), f("email", str()), f("id", str()),
		f("security", str()), f("experiments", str()),
		f("vnext", arr(obj(f("address", str()), f("port", num()), f("users", arr(user))))),
	)
}

func trojanSettings() *node {
	server := obj(f("address", str()), f("port", num()), f("level", num()), f("email", str()), f("password", str()), f("flow", str()))
	return obj(
		f("address", str()), f("port", num()), f("level", num()), f("email", str()), f("password", str()), f("flow", str()),
		f("servers", arr(server)),
	)
}

// shadowsocksMethods are the ciphers of the release: the four AEAD ciphers with their
// aliases (proxy/shadowsocks) and the three of Shadowsocks 2022 (shadowsocks_2022).
// The loader folds them with strings.ToLower, and a value outside this list can
// never be accepted.
func shadowsocksMethods() *node {
	return enumOf(false,
		"aes-128-gcm", "aead_aes_128_gcm=aead_aes_128_gcm", "aes-256-gcm", "aead_aes_256_gcm=aead_aes_256_gcm",
		"chacha20-poly1305", "aead_chacha20_poly1305=aead_chacha20_poly1305", "chacha20-ietf-poly1305",
		"xchacha20-poly1305", "aead_xchacha20_poly1305=aead_xchacha20_poly1305", "xchacha20-ietf-poly1305",
		"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
	)
}

func shadowsocksSettings() *node {
	server := obj(f("address", str()), f("port", num()), f("level", num()), f("email", str()),
		f("method", shadowsocksMethods()), f("password", str()))
	return obj(
		f("address", str()), f("port", num()), f("level", num()), f("email", str()),
		f("method", shadowsocksMethods()), f("password", str()),
		f("servers", arr(server)),
	)
}

func socksSettings() *node {
	user := obj(f("user", str()), f("pass", str()), f("level", num()), f("email", str()))
	return obj(
		f("address", str()), f("port", num()), f("level", num()), f("email", str()), f("user", str()), f("pass", str()),
		f("servers", arr(obj(f("address", str()), f("port", num()), f("users", arr(user))))),
	)
}

func httpSettings() *node {
	user := obj(f("user", str()), f("pass", str()), f("level", num()), f("email", str()))
	return obj(
		f("address", str()), f("port", num()), f("level", num()), f("email", str()), f("user", str()), f("pass", str()),
		f("headers", strMap()),
		f("servers", arr(obj(f("address", str()), f("port", num()), f("users", arr(user))))),
	)
}

func hysteriaSettings() *node {
	return obj(f("version", num()), f("address", str()), f("port", num()))
}

// wireguardSettings: the loader makes an outbound a client by setting IsClient before
// it reads the JSON, and the field has an empty json tag, so a member "isClient" of
// false would turn the outbound into a server. It is refused. noKernelTun is always
// true: the node has no capability to open a kernel interface.
func wireguardSettings() *node {
	peer := obj(f("publicKey", str()), f("preSharedKey", str()), f("endpoint", str()), f("keepAlive", num()),
		f("allowedIPs", arr(str())), f("level", num()), f("email", str()))
	return obj(
		f("noKernelTun", boolean()), f("secretKey", str()), f("address", arr(str())), f("peers", arr(peer)),
		f("mtu", num()), f("reserved", arr(num())), f("remoteDNS", arr(str())),
	).refusing("isClient", "turns the client into a server").forcing("noKernelTun")
}

// freedomSettings holds what a freedom hop may carry. finalRules and ipsBlocked are
// ours: the agent writes the rules of 7.4 on every freedom outbound, so a rule of the
// user's would only suggest that it applies.
func freedomSettings() *node {
	noise := obj(f("type", str()), f("packet", str()), f("delay", rng()), f("applyTo", str()))
	return obj(
		f("targetStrategy", str()), f("domainStrategy", str()), f("userLevel", num()),
		f("fragment", obj(f("packets", str()), f("length", rng()), f("interval", rng()), f("maxSplit", rng()))),
		f("noise", noise), f("noises", arr(noise)), f("proxyProtocol", num()),
	).refusing("finalRules", "the node writes the final rules of every freedom outbound").
		refusing("ipsBlocked", "the node writes the final rules of every freedom outbound")
}

// ---- stream settings --------------------------------------------------------------

func streamSettings() *node {
	return obj(
		f("address", str()), f("port", num()),
		f("method", transportEnum()),
		f("security", enumOf(false, "", "none=none", "tls", "reality")),
		f("finalmask", finalmask()),
		f("tlsSettings", tlsSettings()),
		f("realitySettings", realitySettings()),
		f("rawSettings", rawSettings()),
		f("xhttpSettings", lazy(xhttpSettings)),
		f("kcpSettings", kcpSettings()),
		f("grpcSettings", grpcSettings()),
		f("wsSettings", wsSettings()),
		f("httpupgradeSettings", httpUpgradeSettings()),
		f("hysteriaSettings", obj(f("version", num()), f("auth", str()), f("udpIdleTimeout", num()))),
		f("sockopt", sockopt()),
	).aliased("method", "network").
		aliased("rawSettings", "tcpSettings").
		aliased("xhttpSettings", "splithttpSettings").
		refusing("masqueSettings", "the masque transport belongs to the masque outbound, which is not allowed")
}

// transportEnum is the value of "method" (formerly "network"). The loader folds it
// with strings.ToLower and names the old spellings; the new ones are written.
// h2, h3, http and quic are removed from the release and quic, masque and xdrive
// are never allowed, so they are not here.
func transportEnum() *node {
	return enumOf(false,
		"raw=raw", "tcp=raw", "xhttp=xhttp", "splithttp=xhttp", "kcp=kcp", "mkcp=kcp",
		"grpc", "ws=ws", "websocket=ws", "httpupgrade", "hysteria",
	)
}

func tlsSettings() *node {
	cert := obj(f("certificate", strList()), f("key", strList()), f("usage", str()), f("ocspStapling", num()),
		f("oneTimeLoading", boolean()), f("buildChain", boolean()))
	return obj(
		f("allowInsecure", boolean().refusingTrue("the release refuses allowInsecure; pin the certificate with pinnedPeerCertSha256")), f("certificates", arr(cert)), f("serverName", str()), f("alpn", strList()),
		f("enableSessionResumption", boolean()), f("disableSystemRoot", boolean()), f("minVersion", str()),
		f("maxVersion", str()), f("cipherSuites", str()), f("fingerprint", str()), f("curvePreferences", strList()),
		f("pinnedPeerCertSha256", str()), f("verifyPeerCertByName", str()), f("echConfigList", checked(checkECHList)),
		f("echSockopt", sockopt()), f("useSystemCA", boolean()),
	)
}

func realitySettings() *node {
	return obj(
		f("show", boolean()), f("fingerprint", str()), f("serverName", str()), f("password", str()),
		f("publicKey", str()), f("shortId", str()), f("mldsa65Verify", str()), f("spiderX", checked(checkSpiderX)),
	)
}

func rawSettings() *node {
	hdrs := &node{k: kStrMap}
	req := obj(f("version", str()), f("method", str()), f("path", strList()), f("headers", hdrs))
	resp := obj(f("version", str()), f("status", str()), f("reason", str()), f("headers", hdrs))
	return obj(
		f("header", obj(f("type", enumOf(true, "none", "http")), f("request", req), f("response", resp))),
	)
}

func xhttpSettings() *node {
	xmux := obj(f("maxConcurrency", rng()), f("maxConnections", rng()), f("cMaxReuseTimes", rng()),
		f("hMaxRequestTimes", rng()), f("hMaxReusableSecs", rng()), f("hKeepAlivePeriod", num()))
	return obj(
		f("host", str()), f("path", str()), f("mode", str()), f("headers", strMap()),
		f("xPaddingBytes", rng()), f("xPaddingObfsMode", boolean()), f("xPaddingKey", str()),
		f("xPaddingHeader", str()), f("xPaddingPlacement", str()), f("xPaddingMethod", str()),
		f("uplinkHTTPMethod", str()), f("sessionIDPlacement", str()), f("sessionIDKey", str()),
		f("sessionIDTable", str()), f("sessionIDLength", rng()), f("seqPlacement", str()), f("seqKey", str()),
		f("uplinkDataPlacement", str()), f("uplinkDataKey", str()), f("uplinkChunkSize", rng()),
		f("noGRPCHeader", boolean()), f("noSSEHeader", boolean()), f("scMaxEachPostBytes", rng()),
		f("scMinPostsIntervalMs", rng()), f("scMaxBufferedPosts", num()), f("scStreamUpServerSecs", rng()),
		f("serverMaxHeaderBytes", num()), f("xmux", xmux),
		f("downloadSettings", lazy(streamSettings)),
		// "extra" is read again by the loader as xhttp settings, so it is judged as such.
		f("extra", lazy(xhttpSettings)),
		f("h2Params", raw()),
	)
}

func kcpSettings() *node {
	return obj(
		f("mtu", num()), f("tti", num()), f("uplinkCapacity", num()), f("downlinkCapacity", num()),
		f("cwndMultiplier", num()), f("maxSendingWindow", num()), f("header", raw()), f("seed", str()),
	)
}

func grpcSettings() *node {
	return obj(
		f("authority", str()), f("serviceName", str()), f("multiMode", boolean()), f("idle_timeout", num()),
		f("health_check_timeout", num()), f("permit_without_stream", boolean()), f("initial_windows_size", num()),
		f("user_agent", str()),
	)
}

func wsSettings() *node {
	return obj(f("host", str()), f("path", str()), f("headers", strMap()), f("heartbeatPeriod", num()))
}

func httpUpgradeSettings() *node {
	return obj(f("host", str()), f("path", str()), f("headers", strMap()))
}

// sockopt: mark, tproxy, acceptProxyProtocol, interface and customSockopt reach the
// host's socket options and are on the global list of always-rejected keys.
func sockopt() *node {
	return obj(
		f("tcpFastOpen", anyScalar()), f("domainStrategy", str()), f("dialerProxy", dialerTag()),
		f("tcpKeepAliveInterval", num()), f("tcpKeepAliveIdle", num()), f("tcpCongestion", str()),
		f("tcpWindowClamp", num()), f("tcpMaxSeg", num()), f("penetrate", boolean()), f("tcpUserTimeout", num()),
		f("v6only", boolean()), f("tcpMptcp", boolean()),
		f("happyEyeballs", obj(f("prioritizeIPv6", boolean()), f("tryDelayMs", num()), f("interleave", num()), f("maxConcurrentTry", num()))),
		f("trustedXForwardedFor", arr(str())),
	)
}

// finalmask: the masks whose settings are plain values are in the table. The others
// (header-custom, xdns, xicmp, xmc, realm) have nested programs of their own and stop
// at a warning, so the admin names them in accept_unknown. "script" of a noise mask is
// Lua and is on the global list.
func finalmask() *node {
	mask := func(settings map[string]*node) *node {
		kinds := make([]string, 0, len(settings))
		for k := range settings {
			kinds = append(kinds, k)
		}
		return obj(f("type", enumOf(true, kinds...)), f("settings", raw())).withVariant("type", "settings", settings)
	}
	rg := rng()
	tcp := mask(map[string]*node{
		"filter": obj(f("blockedSourceIPs", arr(str())), f("allowedSourceIPs", arr(str()))),
		"fragment": obj(f("packets", str()), f("length", rg), f("delay", rg), f("lengths", arr(rg)), f("delays", arr(rg)),
			f("maxSplit", rg)),
		"sudoku": sudoku(),
	})
	noiseItem := obj(f("rand", rg), f("randRange", rg), f("type", str()), f("packet", raw()), f("delay", rg))
	udp := mask(map[string]*node{
		"filter":      obj(f("blockedSourceIPs", arr(str())), f("allowedSourceIPs", arr(str()))),
		"mkcp-legacy": obj(f("header", str()), f("value", str())),
		"noise":       obj(f("reset", rg), f("noise", arr(noiseItem))),
		"salamander":  obj(f("password", str()), f("packetSize", rg)),
		"sudoku":      sudoku(),
		"udphop":      obj(f("mode", str()), f("interval", rg), f("remoteIPs", arr(str())), f("remotePorts", rng())),
	})
	quic := obj(
		f("congestion", str()), f("bbrProfile", str()), f("brutalUp", anyScalar()),
		f("brutalDown", anyScalar()), f("brutalDisableLossCompensation", boolean()),
		f("initStreamReceiveWindow", num()), f("maxStreamReceiveWindow", num()),
		f("initConnectionReceiveWindow", num()), f("maxConnectionReceiveWindow", num()),
		f("maxIdleTimeout", num()), f("keepAlivePeriod", num()), f("disablePathMTUDiscovery", boolean()),
		f("disableChromeParrot", boolean()), f("disableGSO", boolean()), f("maxIncomingStreams", num()),
		f("disableStatelessReset", boolean()),
	).refusing("debug", "sets HYSTERIA_BBR_DEBUG and HYSTERIA_BRUTAL_DEBUG in the environment of the process")
	return obj(f("tcp", arr(tcp)), f("udp", arr(udp)), f("quicParams", quic))
}

func sudoku() *node {
	return obj(
		f("password", str()), f("ascii", str()), f("customTable", str()), f("custom_table", str()),
		f("customTables", arr(str())), f("custom_tables", arr(str())), f("paddingMin", num()),
		f("padding_min", num()), f("paddingMax", num()), f("padding_max", num()),
	)
}

// ---- state that rmo leaves behind ------------------------------------------------

// statefulRules classifies every protocol and every transport of the table (7.2,
// finding 4): rmo only drops the tag of an outbound and never closes its handler, so
// a wireguard device with its UDP socket, a hysteria session and an xhttp session over
// h3 stay up until the process ends. A change to such a config therefore rebuilds in
// the idle slot (7.5 step 5). Each protocol and transport of the table is named here,
// so a release that adds one fails TestEveryProtocolAndTransportIsClassified until
// someone has read its handler for the same property (G4).
func statefulRules() statefulSet {
	return statefulSet{
		protocols: map[string]bool{
			"vless": false, "vmess": false, "trojan": false, "shadowsocks": false, "socks": false,
			"http": false, "freedom": false, "hysteria": true, "wireguard": true,
		},
		transports: map[string]transportState{
			"raw": never, "kcp": never, "grpc": never, "ws": never, "httpupgrade": never,
			"hysteria": always, "xhttp": withH3,
		},
	}
}
