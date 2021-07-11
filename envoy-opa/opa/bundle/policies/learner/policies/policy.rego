package policies.policy

import input.attributes.request.http as http_request

federationId := "50f967d4-b9db-4528-950c-b9f0332e63ba"
sub := split(token.payload.sub, ":")

publicRoleCheck {
  api_roles := {"roles": ["PUBLIC"]}
  token.payload.roles[_].role == api_roles.roles[_]
}

federationIdCheck {
  federationId == sub[1]
}

token := {"payload": payload} {
  [_, encoded] := split(http_request.headers.authorization, " ")
  [_, payload, _] := io.jwt.decode(encoded)
}

getUserProfileV3 {
  publicRoleCheck
  federationIdCheck
  split(http_request.path, "/")[4] == sub[2]
}

searchUser {
  publicRoleCheck
  federationIdCheck
  input.parsed_body.request.filters.id == sub[2]
}

userExistenceApi {
  publicRoleCheck
  federationIdCheck
}