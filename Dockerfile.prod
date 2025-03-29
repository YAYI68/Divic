FROM node:18

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY prisma ./prisma

RUN npx prisma generate

COPY . .

RUN npm run build

RUN rm -rf ./src

EXPOSE 3000

CMD [ "npm", "run", "start:prod" ]