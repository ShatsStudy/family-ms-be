# Setup
In order to succesfully start the server you must prepare this environment variables
* MONGO_CONNECT: connection string to mongo DB
* JWT_SECRET: secret for jwt authorization (any string)


# ENDPOINTS
**POST /api/v1/auth/signup** <br/>
## Request
body: 
* login: Login of new user
* password: Password of new user
* firstName: First name of new user
* lastName: Last name of new user
* position: Position of new user
* email: Email adress of new user
* phone: Phone number of new user
* type: Type of new user
* manager (optional): ID of manager of new user
* teamlead (optional): ID of teamlead of new user
* department (optional): ID of department of new user
* photoURL (optional): URL to photo of new user
* hr (optional): ID of hr of new user
## Response
* user: Object of newly created user
**OR if error occures**
* err: Error object
------
**POST /api/v1/auth/login** <br/>
## Request
body: 
* login: Login for user loging in
* password: Password for user loging in
## Response
* token: JWT token of loged in user
**OR if error occures**
* err: Error object
------
**GET /api/v1/users** <br/>
## Request
header: 
* Authorization: JWT Token in format "Bearer ${token}"
## Response
* Array of all users objects 
------
**POST /api/v1/users/:id** <br/>
## Request
header: 
* Authorization: JWT Token in format "Bearer ${token}"
## Response
* user: Object of user found by id 
**OR if there is no user with this id**
* err: 'No user found'
**OR if error occures**
* err: Error object
------
**DELETE /api/v1/users** <br/>
## Request
header: 
* Authorization: JWT Token in format "Bearer ${token}" <br/>

body: 
* id: ID of user to be deleted
## Response
* deleted: 'Success'
**OR if there is no user with this id**
* err: 'No user found'
**OR if error occures**
* err: Error object
------
**PUT /api/v1/users** <br/>
## Request
header: 
* Authorization: JWT Token in format "Bearer ${token}" <br/>

body: 
* id: ID of the user to be updated
* password (optional): New password for user
* firstName (optional): New first name for user
* lastName (optional): New last name for user
* position (optional): New position for user
* email (optional): New email for user
* phone (optional): New phone number for user
* type (optional): New type for user
* manager (optional): ID of new managerfor user
* teamlead (optional): ID of new teamlead for user
* department (optional): ID of new department for user
* photoURL (optional): URL of new photo for user
* hr (optional): ID of new hr  for user
## Response
* user object of updated user
**OR if there is no user with this id**
* err: 'No user found'
**OR if error occures**
* err: Error object
------
**GET /api/v1/issues/all** <br/>
## Response
* Array of all issues objects
**OR if error occures**
* err: Error object
------
**GET /api/v1/issues** <br/>
## Request
query-parameters: status, type, date
## Response
* issue: Object of issues found by priority, type or date 
**OR if there is no issue with this status, type or date**
* err: 'Issue not found'
**OR if error occures**
* err: Error object
------
**POST /api/v1/issues** <br/>
## Request
body: 
* name: Title of new issue
* excerpt: Title of new excerpt
* status: Status name of new issue (Low, Normal or High)
* type: Type of new issue (Task or Issue)
* author: ID of user that create task
* content: Content of new issue
* assignTo: ID of assignTo user
## Response
* added: 'Successfully'
**OR if error occures**
* err: Error object
------
**PUT /api/v1/issues** <br/>
## Request
body: 
* id: ID of the issue to be updated
* name (optional): New name for issue
* excerpt (optional): New excerpt for issue
* status (optional): New status for issue
* content (optional): New value for content
* assignTo (optional): New assignTo for issue
* reassigned (optional): ID of person that makes changes
## Response
* updated: 'Successfully'   
**OR if there is no issue with this id**
* err: 'Issue not found'
**OR if there is no required options**
* err: You should enter assignTo and reassigned options
**OR if error occures**
* err: Error object
------
**DELETE /api/v1/issues** <br/>
## Request
body: 
* id: ID of issue to be deleted
## Response
* deleted: 'Successfully'
**OR if there is no issue with this id**
* err: 'Issue not found'
**OR if error occures**
* err: Error object
------
**GET /api/v1/departments** <br/>
## Response
* Array of all departments objects 
**OR if error occures**
* err: Error object
------
**POST /api/v1/departments** <br/>
## Request
body: 
* title: Title of new title
## Response
* added: 'Successfully'
**OR if error occures**
* err: Error object
------
**GET /api/v1/departments/:id** <br/>
## Response
* department object of department
**OR if there is no issue with this id**
* err: 'Department not found'
**OR if error occures**
* err: Error object
------
**POST /api/v1/departments/users** <br/>
## Request
body: 
* id: Id of department 
* employee: ID of employee that should be added to department

## Response
* added: 'Successfully'
**OR if there is no department with this id**
* err: 'Department not found'
**OR if there is no id of employee**
* err: You should enter id of employee
**OR if error occures**
* err: Error object
------
