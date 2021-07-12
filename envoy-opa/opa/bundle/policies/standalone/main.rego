package main

import input.attributes.request.http as http_request

default allow = false

urls[keys] { urls_to_action_mapping[keys]}   

urls_to_action_mapping := {   
   "/v1/content/search": {"action": "searchContent", "policy": "kmw"},
   "/v3/user/read": {"action": "getUserProfileV3", "policy": "learner"},
   "/v1/user/search": {"action": "searchUser", "policy": "learner"},
   "/v1/user/exists": {"action": "userExistenceApi", "policy": "learner"},
   "/v1/content/state/read": {"action": "readContentState", "policy": "lms"},
   "/v1/content/state/update": {"action": "updateContentState", "policy": "lms"},
   "/v3/search": {"action": "searchContent", "policy": "search"}
}

identified_url := regex.find_n(urls[_], input.path, 1)[0]
identified_action := urls_to_action_mapping[identified_url].action
identified_policy_folder := urls_to_action_mapping[identified_url].policy

allow {
   data.policies.kmw.policy[identified_action]
   data.policies[identified_policy_folder].policy[identified_action]
}