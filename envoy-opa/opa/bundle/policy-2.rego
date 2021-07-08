package envoy.authz.content

default allow = false

allow {
    action_allowed
}

action_allowed {
  api_roles := {"roles": ["CONTENT_CREATOR", "ORG_ADMIN"]}
  some i, j; token.payload.roles[i].role == api_roles.roles[j]
  glob.match("{**/content/v1/create/**,**/v1/content/create/**}", ["/"], input.path)
}

token := {"payload": payload} {
    [_, encoded] := split(input.token, " ")
    [_, payload, _] := io.jwt.decode(encoded)
}
