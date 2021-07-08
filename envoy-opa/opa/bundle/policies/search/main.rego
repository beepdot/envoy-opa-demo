package main

default allow = false

urls[keys] { urls_to_action_mapping[keys]}   

urls_to_action_mapping := {   
   "/v3/search": "searchContent"
}

identified_url := regex.find_n(urls[_], input.path, 1)[0]
identified_action := urls_to_action_mapping[identified_url]

allow {
   data.policies.policy[identified_action]
}