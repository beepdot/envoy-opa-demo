package envoy.authz

action_allowed {
	data.envoy.authz.token.payload.roles[__local6__5].role = "COURSE_CREATOR"
	data.envoy.authz.token.payload.roles[__local6__5].scope[__local7__5].orgId = input.parsed_body.request.content.createdFor[__local8__5]
	__local21__5 = input.attributes.request.http.path
	glob.match("{**/course/v1/create/**,**/v1/course/create/**}", ["/"], __local21__5)
}

action_allowed {
	data.envoy.authz.token.payload.roles[__local6__5].role = "ORG_ADMIN"
	data.envoy.authz.token.payload.roles[__local6__5].scope[__local7__5].orgId = input.parsed_body.request.content.createdFor[__local8__5]
	__local21__5 = input.attributes.request.http.path
	glob.match("{**/course/v1/create/**,**/v1/course/create/**}", ["/"], __local21__5)
}

default allow = false

allow {
	data.envoy.authz.is_token_valid = _term_1_01
	_term_1_01
	data.envoy.authz.action_allowed = _term_1_11
	_term_1_11
}

is_token_valid {
	data.envoy.authz.token.valid = _term_2_02
	_term_2_02
	time.now_ns(__local14__2)
	__local15__2 = __local14__2 / 1000000000
	__local0__2 = __local15__2
	data.envoy.authz.token.payload.nbf = __local18__2
	__local18__2 <= __local0__2
	data.envoy.authz.token.payload.exp = __local19__2
	__local0__2 < __local19__2
}

token = {"valid": __local11__3, "payload": __local13__3} {
	__local22__3 = input.attributes.request.http.headers.authorization
	split(__local22__3, " ", __local16__3)
	[__local9__3, __local10__3] = __local16__3
	io.jwt.decode_verify(__local10__3, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__3)
	[__local11__3, __local12__3, __local13__3] = __local17__3
}
