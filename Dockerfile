FROM denoland/deno:2.1.9

WORKDIR /app

# Cache dependencies first for faster rebuilds.
COPY deno.json deno.lock ./
COPY main.ts ./
COPY src/ ./src/
RUN deno cache main.ts

EXPOSE 8000
# Needs only network (serve) and env (config). No filesystem, no database.
CMD ["deno", "run", "--allow-net", "--allow-env", "main.ts"]
