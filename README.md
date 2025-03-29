# Setting Up DIVIC Project

This guide will walk you through setting up a DIVIC project, including installing dependencies, setting up environment variables, and running the project in development mode.

## Prerequisites

Before getting started, ensure you have the following installed on your system:

- Node.js and npm (Node Package Manager)
- Nest CLI (optional but recommended for creating projects)

## Steps

### 1. Clone the project from Github repository

```bash
git clone https://github.com/YAYI68/divic-assessment.git

```
### 2. Install Dependencies
Navigate into your project directory:

```bash
npm install
```

### 3.  Set Up Environment Variables
Create a .env file in the root of your project. Add the necessary environment variables
```
DATABASE_URL=your postgress database connection url
JWTSECRET=your secret text
REFRESH_SECRET=your refresh secret text
```

### 4. Run the Project in Development Mode
Finally, you can run the project in development mode:
```bash
npm run start:dev
```
it will be accessible at http://localhost:3001.

## Testing the Graphql Api 
You can use desktop postman or the live postman to test your queries,
here is the link to [**view the api**](https://documenter.getpostman.com/view/31453748/2sA35BbQ7i)

## Conclusion 
You have successfully setup the project

