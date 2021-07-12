package kmw

import input.attributes.request.http as http_request

default allow = false

urls[keys] { urls_to_action_mapping[keys]}   

urls_to_action_mapping := {   
   "/v1/content/search": "searchContent"
}

identified_url := regex.find_n(urls[_], http_request.path, 1)[0]
identified_action := urls_to_action_mapping[identified_url]

allow {
   data.policies.kmw.policy[identified_action]
}