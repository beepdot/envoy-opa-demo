package main

default allow = false

urls[keys] { urls_to_action_mapping[keys]}   

urls_to_action_mapping := {   
   "/v1/content/search": {"action": "searchContent", "policy": "content"},
   "/v1/content/state/update": {"action": "updateContentState", "policy": "lms"}
}

identified_url := regex.find_n(urls[_], input.path, 1)[0]
identified_action := urls_to_action_mapping[identified_url].action
identified_policy_folder := urls_to_action_mapping[identified_url].policy

allow {
   data.policies[identified_policy_folder].policy[identified_action]
}