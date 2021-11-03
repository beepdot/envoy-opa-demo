package envoy.authz

default allow = false

allow {
    action_allowed
}

ROLES := {
   "COURSE_CREATOR": ["courseAdmin", "courseCreate", "courseUpdate"],
   "ORG_ADMIN": ["orgCreate"]
}

action_allowed {
  startswith(input.path, "/v1/content/create")
  api_roles := {"roles": ["CONTENT_CREATOR", "ORG_ADMIN"]}
  some i
  token.payload.roles[i].role == api_roles.roles[_]
}

action_allowed {
  startswith(input.path, "/v1/course/create")
  acls := ["courseCreate"]
  some i
  ROLES[token.payload.roles[i].role][_] == acls[_]
  some j, k
  token.payload.roles[i].scope[j].orgId == input.request.content.createdFor[k]  
}

token := {"payload": payload} {
    [_, encoded] := split(input.token, " ")
    [_, payload, _] := io.jwt.decode(encoded) 
}

input := {"path": "/v1/course/create/abc","request": {"content": {"createdFor": ["01269878797503692810"]}}, "token": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiI3ZTcyNjg5OC0wNjM1LTQ0Y2YtODFmZi0zYjNhODg5YzhkYmEiLCJ0eXAiOiJCZWFyZXIiLCJuYmYiOjE1MTQ4NTExMzksImV4cCI6MTY0MTA4MTUzOSwiaWF0IjoxNjIyNjU4MTMyLCJyb2xlcyI6W3sic2NvcGUiOlt7Im9yZ0lkIjoiMDEyNjk4Nzg3OTc1MDM2OTI4MTAifV0sInJvbGUiOiJDT1VSU0VfQ1JFQVRPUiJ9LHsic2NvcGUiOlt7Im9yZ0lkIjoiT1JHXzAwMSJ9LHsib3JnSWQiOiIwMTI2OTg3ODc5NzUwMzY5MjgyMCJ9XSwicm9sZSI6IkNPVVJTRV9DUkVBVE9SIn1dfQ.UxcEHgeYWmF-tDP5FyZfnKYCi2rtEM4SvLnlLGcJPno"}