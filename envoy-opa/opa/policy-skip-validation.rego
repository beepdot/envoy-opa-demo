package envoy.authz

default allow = false

allow {
    action_allowed
}

action_allowed {
  api_roles := {"roles": ["CONTENT_CREATOR", "ORG_ADMIN"]}
  some i, j; token.payload.roles[i].role == api_roles.roles[j]
  startswith(input.path, "/v1/content/create")
}

action_allowed {
  api_roles := {"roles": ["COURSE_CREATOR", "ORG_ADMIN"]}
  some i, j; api_roles.roles[i] == token.payload.roles[j].role; some k, l; token.payload.roles[j].scope[k].orgId == input.request.content.createdFor[l]
  startswith(input.path, "/v1/course/create")
}

token := {"payload": payload} {
    [_, encoded] := split(input.token, " ")
    [_, payload, _] := io.jwt.decode(encoded)
}


#input := {"path": "/v1/course/create/abc","request": {"content": {"createdFor": ["01269878797503692810"]}}, "token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiI3ZTcyNjg5OC0wNjM1LTQ0Y2YtODFmZi0zYjNhODg5YzhkYmEiLCJ0eXAiOiJCZWFyZXIiLCJuYmYiOjE1MTQ4NTExMzksImV4cCI6MTY0MTA4MTUzOSwiaWF0IjoxNjIyNjU4MTMyLCJyb2xlcyI6W3sic2NvcGUiOlt7Im9yZ0lkIjoiMDEyNjk4Nzg3OTc1MDM2OTI4MTAifV0sInJvbGUiOiJDT05URU5UX0NSRUFUT1IifSx7InNjb3BlIjpbeyJvcmdJZCI6Ik9SR18wMDEifSx7Im9yZ0lkIjoiMDEyNjk4Nzg3OTc1MDM2OTI4MTAifV0sInJvbGUiOiJDT1VSU0VfQ1JFQVRPUiJ9XX0.O_AxwINa8JwaPK3bIE6ImsA5lBF_AoQyl3OwmyRO3CI"}