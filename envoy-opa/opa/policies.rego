package envoy.authz

import input.attributes.request.http as http_request

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
  glob.match("{**/content/v1/create/**,**/v1/content/create/**}", ["/"], "/api/content/v1/create/abc")
}

action_allowed {
  api_roles := {"roles": ["COURSE_CREATOR", "ORG_ADMIN"]}
  some i, j; api_roles.roles[i] == token.payload.roles[j].role; some k, l; token.payload.roles[j].scope[k].orgId == input.parsed_body.request.content.createdFor[l]
  glob.match("{**/course/v1/create/**,**/v1/course/create/**}", ["/"], http_request.path)
}

token := {"valid": valid, "payload": payload} {
    [_, encoded] := split("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJteWtleSIsImF1ZCI6InN1bmJpcmQiLCJ1c2VyaWQiOiI3ZTcyNjg5OC0wNjM1LTQ0Y2YtODFmZi0zYjNhODg5YzhkYmEiLCJ0eXAiOiJCZWFyZXIiLCJuYmYiOjE1MTQ4NTExMzksImV4cCI6MTY0MTA4MTUzOSwiaWF0IjoxNjIyNjU4MTMyLCJyb2xlcyI6W3sic2NvcGUiOlt7Im9yZ0lkIjoiMDEyNjk4Nzg3OTc1MDM2OTI4MTAifV0sInJvbGUiOiJCT09LX0NSRUFUT1IifSx7InNjb3BlIjpbeyJvcmdJZCI6Ik9SR18wMDEifSx7Im9yZ0lkIjoiMDEyNjk4Nzg3OTc1MDM2OTI4MTAifV0sInJvbGUiOiJDT05URU5UX0NSRUFUT1IifV19.uYkqJqNL_V_0HqyNRel073zWzel9CIoDcPvPy5bmcK8", " ")
    [valid, _, payload] := io.jwt.decode_verify(encoded, {"secret": "secret", "iss": "mykey", "aud": "sunbird"})
}
