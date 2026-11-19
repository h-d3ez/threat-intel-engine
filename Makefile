.PHONY: up down logs test demo
up:
	cp -n .env.example .env || true
	docker compose up --build -d
down:
	docker compose down
logs:
	docker compose logs -f api worker
test:
	pytest -q
demo:
	docker compose --profile demo run --rm simulator
