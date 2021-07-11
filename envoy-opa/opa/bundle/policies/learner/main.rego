package main

import input.attributes.request.http as http_request

default allow = false

urls[keys] { urls_to_action_mapping[keys]}   

urls_to_action_mapping := {   
   "/v3/user/read": "getUserProfileV3",
   "/v1/user/search": "searchUser",
   "/v1/user/exists": "userExistenceApi"
}

identified_url := regex.find_n(urls[_], http_request.path, 1)[0]
identified_action := urls_to_action_mapping[identified_url]

allow {
   data.policies.policy[identified_action]
}