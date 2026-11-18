# Banish API and dashboard (the central ban registry).
#   docker build -t banish-api .
#   docker run -p 5380:5380 -v banish-data:/var/lib/banish -v ./banish.json:/etc/banish/banish.json:ro banish-api
# The agent is not containerised: it edits the host firewall and reads host logs.

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props Majorsilence.Banish.slnx ./
COPY src ./src
RUN dotnet publish src/Majorsilence.Banish.Api -c Release -o /out
RUN dotnet publish src/Majorsilence.Banish.Cli -c Release -o /out-cli

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /out ./
COPY --from=build /out-cli /app/cli
# Inside a container the API must listen on all interfaces; put TLS in front of it (reverse proxy).
ENV BANISH_CONFIG=/etc/banish/banish.json \
    BANISH__Api__Urls=http://0.0.0.0:5380
RUN mkdir -p /var/lib/banish && chown -R $APP_UID /var/lib/banish
USER $APP_UID
VOLUME /var/lib/banish
EXPOSE 5380
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["dotnet", "/app/banish-api.dll", "--healthcheck"]
ENTRYPOINT ["dotnet", "/app/banish-api.dll"]
