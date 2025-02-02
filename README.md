# Auth microservices

## Steps for dev environment

1. Clone the repository
2. Install dependencies
3. Create file `.env` based on `.env.template`
4. Execute Prisma migrate `npx prisma migrate dev`
5. Start up nast server
    ```
    docker run -d --name nats-main -p 4222:4222 -p 6222:6222 -p 8222:8222 nats
    ```
6. Execute `npm run start:dev` or `yarn start:dev`
