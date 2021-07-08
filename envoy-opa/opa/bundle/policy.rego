package envoy.authz

default allow = false

allow {
   action_allowed 
}

action_allowed {
  api_roles := {"roles": ["COURSE_CREATOR", "ORG_ADMIN"]}
  some i, j; api_roles.roles[i] == token.payload.roles[j].role; some k, l; token.payload.roles[j].scope[k].orgId == input.request.content.createdFor[l]
  glob.match("{**/course/v1/create/**,**/v1/course/create/**}", ["/"], input.path)
}

token := {"payload": payload} {
    [_, encoded] := split(input.token, " ")
    [_, payload, _] := io.jwt.decode(encoded)
}
