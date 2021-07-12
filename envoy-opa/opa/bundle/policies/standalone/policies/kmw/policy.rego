package policies.kmw.policy

import input.attributes.request.http as http_request

token := {"payload": payload} {
    [_, encoded] := split(http_request.headers.authorization, " ")
    [_, payload, _] := io.jwt.decode(encoded)
}

searchContent {
  api_roles := {"roles": ["PUBLIC"]}
  token.payload.roles[_].role == api_roles.roles[_]
}
