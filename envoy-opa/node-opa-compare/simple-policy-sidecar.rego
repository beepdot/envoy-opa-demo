package envoy.authz

default allow = false

allow {
    action_allowed
}

action_allowed {
  input.parsed_body.request.courseId
  input.parsed_body.request.batchId
} 
