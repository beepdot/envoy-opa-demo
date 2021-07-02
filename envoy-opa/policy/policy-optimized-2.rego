package envoy.authz

default allow = false

allow {
	__local22__3 = input.attributes.request.http.headers.authorization
	split(__local22__3, " ", __local16__3)
	[__local9__3, __local10__3] = __local16__3
	io.jwt.decode_verify(__local10__3, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__3)
	[__local11__3, __local12__3, __local13__3] = __local17__3
	__local11__3 = _term_2_02
	_term_2_02
	time.now_ns(__local14__2)
	__local15__2 = __local14__2 / 1000000000
	__local0__2 = __local15__2

	__local22__4 = input.attributes.request.http.headers.authorization
	split(__local22__4, " ", __local16__4)
	[__local9__4, __local10__4] = __local16__4
	io.jwt.decode_verify(__local10__4, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__4)
	[__local11__4, __local12__4, __local13__4] = __local17__4
	__local13__4 = _ref_02
	_ref_02.nbf = __local18__2
	__local18__2 <= __local0__2

	__local22__5 = input.attributes.request.http.headers.authorization
	split(__local22__5, " ", __local16__5)
	[__local9__5, __local10__5] = __local16__5
	io.jwt.decode_verify(__local10__5, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__5)
	[__local11__5, __local12__5, __local13__5] = __local17__5
	__local13__5 = _ref_12
	_ref_12.exp = __local19__2
	__local0__2 < __local19__2

	__local22__11 = input.attributes.request.http.headers.authorization
	split(__local22__11, " ", __local16__11)
	[__local9__11, __local10__11] = __local16__11
	io.jwt.decode_verify(__local10__11, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__11)
	[__local11__11, __local12__11, __local13__11] = __local17__11
	__local13__11 = _ref_28
	_ref_28.roles[__local6__8].role = "ORG_ADMIN"

	__local22__12 = input.attributes.request.http.headers.authorization
	split(__local22__12, " ", __local16__12)
	[__local9__12, __local10__12] = __local16__12
	io.jwt.decode_verify(__local10__12, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__12)
	[__local11__12, __local12__12, __local13__12] = __local17__12
	__local13__12 = _ref_38
	_ref_38.roles[__local6__8].scope[__local7__8].orgId = input.parsed_body.request.content.createdFor[__local8__8]
	__local21__8 = input.attributes.request.http.path
	glob.match("{**/course/v1/create/**,**/v1/course/create/**}", ["/"], __local21__8)
}

allow {
	__local22__3 = input.attributes.request.http.headers.authorization
	split(__local22__3, " ", __local16__3)
	[__local9__3, __local10__3] = __local16__3
	io.jwt.decode_verify(__local10__3, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__3)
	[__local11__3, __local12__3, __local13__3] = __local17__3
	__local11__3 = _term_2_02
	_term_2_02
	time.now_ns(__local14__2)
	__local15__2 = __local14__2 / 1000000000
	__local0__2 = __local15__2

	__local22__4 = input.attributes.request.http.headers.authorization
	split(__local22__4, " ", __local16__4)
	[__local9__4, __local10__4] = __local16__4
	io.jwt.decode_verify(__local10__4, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__4)
	[__local11__4, __local12__4, __local13__4] = __local17__4
	__local13__4 = _ref_02
	_ref_02.nbf = __local18__2
	__local18__2 <= __local0__2

	__local22__5 = input.attributes.request.http.headers.authorization
	split(__local22__5, " ", __local16__5)
	[__local9__5, __local10__5] = __local16__5
	io.jwt.decode_verify(__local10__5, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__5)
	[__local11__5, __local12__5, __local13__5] = __local17__5
	__local13__5 = _ref_12
	_ref_12.exp = __local19__2
	__local0__2 < __local19__2

	__local22__7 = input.attributes.request.http.headers.authorization
	split(__local22__7, " ", __local16__7)
	[__local9__7, __local10__7] = __local16__7
	io.jwt.decode_verify(__local10__7, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__7)
	[__local11__7, __local12__7, __local13__7] = __local17__7
	__local13__7 = _ref_06
	"CONTENT_CREATOR" = _ref_06.roles[__local2__6].role
	__local20__6 = input.attributes.request.http.path
	glob.match("{**/content/v1/create/**,**/v1/content/create/**}", ["/"], __local20__6)
}

allow {
	__local22__3 = input.attributes.request.http.headers.authorization
	split(__local22__3, " ", __local16__3)
	[__local9__3, __local10__3] = __local16__3
	io.jwt.decode_verify(__local10__3, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__3)
	[__local11__3, __local12__3, __local13__3] = __local17__3
	__local11__3 = _term_2_02
	_term_2_02
	time.now_ns(__local14__2)
	__local15__2 = __local14__2 / 1000000000
	__local0__2 = __local15__2

	__local22__4 = input.attributes.request.http.headers.authorization
	split(__local22__4, " ", __local16__4)
	[__local9__4, __local10__4] = __local16__4
	io.jwt.decode_verify(__local10__4, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__4)
	[__local11__4, __local12__4, __local13__4] = __local17__4
	__local13__4 = _ref_02
	_ref_02.nbf = __local18__2
	__local18__2 <= __local0__2

	__local22__5 = input.attributes.request.http.headers.authorization
	split(__local22__5, " ", __local16__5)
	[__local9__5, __local10__5] = __local16__5
	io.jwt.decode_verify(__local10__5, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__5)
	[__local11__5, __local12__5, __local13__5] = __local17__5
	__local13__5 = _ref_12
	_ref_12.exp = __local19__2
	__local0__2 < __local19__2

	__local22__7 = input.attributes.request.http.headers.authorization
	split(__local22__7, " ", __local16__7)
	[__local9__7, __local10__7] = __local16__7
	io.jwt.decode_verify(__local10__7, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__7)
	[__local11__7, __local12__7, __local13__7] = __local17__7
	__local13__7 = _ref_06
	"ORG_ADMIN" = _ref_06.roles[__local2__6].role
	__local20__6 = input.attributes.request.http.path
	glob.match("{**/content/v1/create/**,**/v1/content/create/**}", ["/"], __local20__6)
}

allow {
	__local22__3 = input.attributes.request.http.headers.authorization
	split(__local22__3, " ", __local16__3)
	[__local9__3, __local10__3] = __local16__3
	io.jwt.decode_verify(__local10__3, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__3)
	[__local11__3, __local12__3, __local13__3] = __local17__3
	__local11__3 = _term_2_02
	_term_2_02
	time.now_ns(__local14__2)
	__local15__2 = __local14__2 / 1000000000
	__local0__2 = __local15__2

	__local22__4 = input.attributes.request.http.headers.authorization
	split(__local22__4, " ", __local16__4)
	[__local9__4, __local10__4] = __local16__4
	io.jwt.decode_verify(__local10__4, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__4)
	[__local11__4, __local12__4, __local13__4] = __local17__4
	__local13__4 = _ref_02
	_ref_02.nbf = __local18__2
	__local18__2 <= __local0__2

	__local22__5 = input.attributes.request.http.headers.authorization
	split(__local22__5, " ", __local16__5)
	[__local9__5, __local10__5] = __local16__5
	io.jwt.decode_verify(__local10__5, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__5)
	[__local11__5, __local12__5, __local13__5] = __local17__5
	__local13__5 = _ref_12
	_ref_12.exp = __local19__2
	__local0__2 < __local19__2

	__local22__9 = input.attributes.request.http.headers.authorization
	split(__local22__9, " ", __local16__9)
	[__local9__9, __local10__9] = __local16__9
	io.jwt.decode_verify(__local10__9, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__9)
	[__local11__9, __local12__9, __local13__9] = __local17__9
	__local13__9 = _ref_08
	_ref_08.roles[__local6__8].role = "COURSE_CREATOR"

	__local22__10 = input.attributes.request.http.headers.authorization
	split(__local22__10, " ", __local16__10)
	[__local9__10, __local10__10] = __local16__10
	io.jwt.decode_verify(__local10__10, {"aud": "sunbird", "iss": "mykey", "secret": "secret"}, __local17__10)
	[__local11__10, __local12__10, __local13__10] = __local17__10
	__local13__10 = _ref_18
	_ref_18.roles[__local6__8].scope[__local7__8].orgId = input.parsed_body.request.content.createdFor[__local8__8]
	__local21__8 = input.attributes.request.http.path
	glob.match("{**/course/v1/create/**,**/v1/course/create/**}", ["/"], __local21__8)
}
