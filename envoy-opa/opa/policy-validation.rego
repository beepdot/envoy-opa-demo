package envoy.authz

default allow = false

allow {
    is_token_valid
    action_allowed
}

is_token_valid {
  token.valid
  now := time.now_ns() / 1000000000
  token.payload.nbf <= now
  now < token.payload.exp
}

action_allowed {
  api_roles := {"roles": ["CONTENT_CREATOR", "ORG_ADMIN"]}
  some i, j; token.payload.roles[i].role == api_roles.roles[j]
  glob.match("{**/content/v1/create/**,**/v1/content/create/**}", ["/"], input.path)
}

action_allowed {
  api_roles := {"roles": ["COURSE_CREATOR", "ORG_ADMIN"]}
  some i, j; api_roles.roles[i] == token.payload.roles[j].role; some k, l; token.payload.roles[j].scope[k].orgId == input.request.content.createdFor[l]
  glob.match("{**/course/v1/create/**,**/v1/course/create/**}", ["/"], input.path)
}

token := {"valid": valid, "payload": payload} {
    [_, encoded] := split(input.token, " ")
    [valid, _, payload] := io.jwt.decode_verify(encoded, {"secret": "secret"})
}
