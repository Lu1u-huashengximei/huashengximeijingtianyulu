FROM node:22-slim

WORKDIR /app

# 零依赖项目，仅复制运行所需文件
COPY package.json ./
COPY server.js recorder.html ./

# 云托管默认探测端口；用环境变量 PORT 可被平台覆盖
ENV PORT=80
EXPOSE 80

CMD ["node", "server.js"]
