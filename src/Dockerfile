FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
LABEL maintainer="edi.wang@outlook.com"

EXPOSE 8080

WORKDIR /src
COPY CIDRCalc.csproj .
RUN dotnet restore CIDRCalc.csproj
COPY . .
RUN dotnet build CIDRCalc.csproj -c Release -o /app/build

FROM build AS publish
RUN dotnet publish CIDRCalc.csproj -c Release -o /app/publish

FROM nginx:alpine AS final
WORKDIR /usr/share/nginx/html
COPY --from=publish /app/publish/wwwroot .
COPY nginx.conf /etc/nginx/nginx.conf