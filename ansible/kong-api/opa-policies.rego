createContent {
  api_roles := {"roles": ["CONTENT_CREATOR", "COURSE_CREATOR"]}
  some i, j, k
  api_roles.roles[_] == token.payload.roles[i].role
  token.payload.roles[i].scope[j].orgId == input.parsed_body.request.content.createdFor[k]
  sub := split(token.payload.sub, ":")
  http_request.headers.x-user-id == sub[2]
}