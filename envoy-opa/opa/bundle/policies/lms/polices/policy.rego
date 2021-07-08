package policies.policy

import input.attributes.request.http as http_request

federationId := "50f967d4-b9db-4528-950c-b9f0332e63ba"

token := {"payload": payload} {
    [_, encoded] := split(http_request.headers.authorization, " ")
    [_, payload, _] := io.jwt.decode(encoded)
}

updateContentState {
  api_roles := {"roles": ["PUBLIC"]}
  sub := split(token.payload.sub, ":")
  federationId == sub[1]
  input.parsed_body.request.userId == sub[2]
  some i, j, k, l, m; token.payload.roles[i].role == api_roles.roles[j]; token.payload.roles[i].scope[k].courseIds[l]; l == input.parsed_body.request.contents[m].courseId; token.payload.roles[i].scope[k].courseIds[l].batchId == input.parsed_body.request.contents[m].batchId
}