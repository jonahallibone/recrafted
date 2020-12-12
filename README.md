### Getting started

Clone the repo and perform an `npm install`

# Note on Prisma
It is installed as a devDependency, which means access to the cli granted via `npx`

For example:
```
npx prisma generate --watch
```
will watch and generate models as the db schema changes

## Step 1: Get MySQL set up
Make sure docker is installed and active. Navigate into the root directory and run
```
docker-compose up -d
```
To confirm this works, run `docker ps`. It should list something similar to
```
CONTAINER ID   IMAGE          COMMAND                  CREATED          STATUS          PORTS                               NAMES
542eb3bfd4f7   mysql:8.0.22   "docker-entrypoint.s…"   x minutes ago    Up x minutes    33060/tcp, 0.0.0.0:3308->3306/tcp   recrafted_db_1
```
## Step 2: npm

run `npm i`

## Step 3: prisma

Getting prisma set is pretty easy.

- Run `npx prisma generate` to generate the binary for the models. 
- - You could also continuously generate with `npx prisma generate --watch`

Now that the binary is generated, run command `npx prisma migrate dev --preview-feature`

This should connect to the database and create the schema. 

## Step 4: develop

Run `npm run dev` and check `http://localhost:3000`


