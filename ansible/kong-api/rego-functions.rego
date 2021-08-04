token := {
  "roles": [
    {
      "scope": [
        {
          "orgId": "01269878797503692810"
        }
      ],
      "role": "COURSE_CREATOR"
    },
    {
      "scope": [
        {
          "orgId": "ORG_001"
        },
        {
          "orgId": "ORG_002"
        }
      ],
      "role": "BOOK_CREATOR"
    }
  ]
}

request := {
   "content": {
     "name": "Test",
     "primaryCategory": "eTextbook",
     "description": "Enter description for Resource",
     "createdBy": "7e726898-0635-44cf-81ff-3b3a889c8dba",
     "organisation": [
       "Tamil Nadu"
     ],
     "createdFor": [
       "01269878797503692810"
     ],
     "contentType": "Resource",
     "framework": "tn_k-12_5",
     "mimeType": "application/vnd.ekstep.ecml-archive",
     "resourceType": "Learn",
     "creator": "cc tn"
   }
 }


role_check(api_roles) {
    api_roles[_] == token.roles[_].role
}

org_check(key) {
  some i
  api_roles.roles[_] == token.roles[i].role
  request = 
  some j, k; token.roles[i].scope[j].orgId == 
}

org_check(key) = r {
   r = replace(key, `*`, "l")
}

role_check(["BOOK_CREATOR", "COURSE_CREATOR"])
org_check("request.content.createdFor[*]")