FROM microsoft/aspnetcore:2.0 AS base
WORKDIR /app
EXPOSE 5006
EXPOSE 44304

FROM microsoft/aspnetcore-build:2.0 AS build
WORKDIR /src
COPY EpubLibrary/EpubLibrary.csproj EpubLibrary/
RUN dotnet restore EpubLibrary/EpubLibrary.csproj
COPY . .
WORKDIR /src/EpubLibrary
RUN dotnet build EpubLibrary.csproj -c Release -o /app

FROM build AS publish
RUN dotnet publish EpubLibrary.csproj -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "EpubLibrary.dll"]
