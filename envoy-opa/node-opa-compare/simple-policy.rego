package envoy.authz

default allow = false

allow {
    action_allowed
}

action_allowed {
  input.request.courseId
  input.request.batchId
}
