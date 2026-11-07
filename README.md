# Task 5 (Variant): Course Review Board - With Instructor Dashboard

We will building on top of the course review variant in task 3. Previously we implemented `JWT` authentication and now a new model and controller have been added. Let us first start with some context.
## Context

### Injection attacks

An Injection attack vector is a class of security vulnerabilities where the system is susceptible to receiving input from an untrusted user that is part used as part of a Command or a Query for an interpreter. These include, but not limited to, databases, OS Shell, or an XML Parser. The interpreter unwittingly executes the malicious payload as code instead of treating it as plain data. Injection attacks come in multiple formats Such as:

- `SQL Injection`:  Malicious users insert malicious `SQL` statements into data entry fields or login forms to manipulate backend database queries. This can bypass authentication or extract, modify, and delete sensitive records.
- `OS Command Injection`: Attackers inject operating system commands into vulnerable web applications, forcing the host server to run arbitrary terminal or shell commands with the application's privileges.

The above two are just two examples of many possibilities. For today's task we will be focusing on `NoSQL Injection Attacks`.


### `NoSQL Injection Attack`

A `NoSQL` Injection attack is a subclass of the Injection attacks. It is a security vulnerability that happens when an application passes unsanitized user input directly into a non-relational database query (such as MongoDB, Redis, or Cassandra). Unlike traditional SQL Databases, `NoSQL` databases often use `JSON-like` objects, JavaScript functions, or special operators to filter data; if an application fails to validate or restrict what kind of data a user can send, an attacker can substitute a malicious operator or object instead of a normal text string.

#### How it works:

1. **Unsanitized Inputs**: The web application accepts user data (like a login form or search box) and builds a database query dynamically.
2. **Injecting Objects or Operators**: Instead of typing plain text into a field, an attacker injects a special `NoSQL` operator (such as `$ne` for "not equal" or `$where`) or a structured object.
3. **Altered Logic**: The database interprets the injected input as part of the command logic rather than literal data, changing what records are matched.

## Running it

```bash
npm install           # Install concurrently and the dependencies of the projects
npm run install:all   # For safety
npm run dev           # API on :4000, client on :5175
```

Create the `server/.env` file.

```ini
PORT=4000
MONGO_URI=mongodb://tasks:pass1234@ac-j3acrgb-shard-00-00.lueesfz.mongodb.net:27017,ac-j3acrgb-shard-00-01.lueesfz.mongodb.net:27017,ac-j3acrgb-shard-00-02.lueesfz.mongodb.net:27017/?ssl=true&replicaSet=atlas-6to6iy-shard-0&authSource=admin&appName=Cluster0
JWT_SECRET=4a498d90a0f923ae4b3f1f65571ff25985d17e2f3286e8e90383e449f68a40a8
JWT_EXPIRES_IN=7d
```

## What was added on top of Task 3
<details>
<summary> View details </summary>

### Server

- Added a new model called Instructor with the following attributes: `name`, `username`, `password`, `department`, `role` `apiKey`, `privateEmail`, `privatePhone`.
- Added the Instructor Controller with the following routes:
	- `/api/instructors/login`: This is the login function that is dedicated to the instructors to be able to access the instructor Dashboard in the Client.
	- `/api/instructors/`: This function is used to get all of the instructors with limited fields.
	- `/api/instructors/search`: This function is used to search for instructors using query parameters.

### Client

- Added The `InstructorLogin.jsx` and the `InstructorDashboard.jsx` pages.

---



</details>

## Simulating the Attack

For this you will need to use postman to some extent. Look through the `Flow.md` Markdown file for the detailed steps to simulate the `NoSQL` injection.

Please note that Attack 4 will not work due to MongoDB being on the Free Tier, but it is still a real attack vector that you must protect against (Details in the `Flow.md` file). After reading the file Read the next section.

## Task

<details>

<summary>View Task</summary>

Every attack from the `Flow.md` file works because the Instructor controller (`instructorController.js`) trusts request input and feeds it directly into Mongoose, with no validation and no sanitation.

**Fix it.** Make the login and search safe while keeping their legitimate behavior, then re-run every attack in this file and confirm each one now fails. Think about: validating/typing input, rejecting query operators from clients, not storing plain-text passwords, and not returning secret fields.

Your solution should utilize the `express-mongo-sanitize` package and you are expected to know the difference between `Joi` and `express-mongo-sanitize` and think carefully about which properties should be public and which should be kept private.

</details>
