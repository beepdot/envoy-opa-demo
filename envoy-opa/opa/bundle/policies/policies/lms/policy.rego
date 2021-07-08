package policies.lms.policy

federationId := "50f967d4-b9db-4528-950c-b9f0332e63ba"

token := {"payload": payload} {
    [_, encoded] := split(input.token, " ")
    [_, payload, _] := io.jwt.decode(encoded)
}

updateContentState {
  api_roles := {"roles": ["PUBLIC"]}
  sub := split(token.payload.sub, ":")
  federationId == sub[1]
  sub[2] == request.userId
  token.payload.roles[_].role == api_roles.roles[_]
  some i, j; 
  token.payload.roles[i].scope[j].courseId == request.contents.courseId
  token.payload.roles[i].scope[j].batchId == request.contents.batchId
}