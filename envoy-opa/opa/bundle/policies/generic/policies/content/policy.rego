package policies.content.policy

token := {"payload": payload} {
    [_, encoded] := split(input.token, " ")
    [_, payload, _] := io.jwt.decode(encoded)
}

searchContent {
  api_roles := {"roles": ["PUBLIC"]}
  token.payload.roles[_].role == api_roles.roles[_]
}