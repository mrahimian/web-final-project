# http-monitor

A HTTP endpoint monitor service written in python with RESTful API.

Web framework [Echo](https://echo.labstack.com/)

## Database

#### Tables : 

**Users:**

| id(pk)  | created_at | username     | password     |
| :------ | ---------- | ------------ | ------------ |
| integer | datetime   | varchar(100) | varchar(100) |

**URLs:**

| id(pk)  | created_at | user_id(fk) | address      | threshold | failed_times |
| ------- | ---------- | ----------- | ------------ | --------- | :----------- |
| integer | datetime   | integer     | varchar(100) | integer   | integer      |

**Requests:**

| id(pk)  | created_at | url_id(fk) | code    |
| ------- | ---------- | ---------- | ------- |
| integer | datetime   | integer    | integer |

## API

### Specs:

For all requests and responses we have `Content-Type: application/json`.

Authorization is with JWT.

#### User endpoints:

**Login:**

`POST /login`

request structure: 

```
{
	"username":"foo", 
	"password":"*bar*" 
}
```

**Register:**

`POST /register`

request structure (same as login):

```
{
	"username":"foo", // alpha numeric, length >= 4
	"password":"*bar*" // text, length >=4 
}
```

#### URL endpoints:

**Create URL:**

`POST /urls`

request structure:

```
{
	"address":"http://some-valid-url.com" // valid url address
	"threshold":20 // url fail threshold
}
```

##### **Get user URLs:**

`GET /urls`

**Get URL stats:**

`GET /urls/:urlID`

`urlID` a valid url id

**Get URL alerts:**

`GET /alerts`
