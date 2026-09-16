# Concepta — быстрый старт

Детекция emerging-угроз в потоке кибербезопасности. **Единый Docker-образ**
запускает оба процесса в одном контейнере:

| Процесс | Стек | Порт | Описание |
|---------|------|------|----------|
| `uvicorn` (NCD) | Python (FastAPI) | `5000 → 8080` | NCD-движок: эмбеддинги, UMAP, кластеризация, LLM |
| `dotnet` (API) | .NET 10 (ASP.NET) | `5001` | HTTP API, парсинг RSS/NVD, хранение, SignalR |

## Запуск через Docker

Требуется Docker + Docker Compose.

```bash
# из корня репозитория
docker compose up --build -d
```

или без compose:

```bash
docker build -t concepta .
docker run -d --name concepta -p 5000:8080 -p 5001:5001 \
       -v concepta-data:/data concepta
```

Первый запуск долгий (~10–15 мин): качается образ Python с torch (CPU ~200 МБ),
ASP.NET runtime и embedding-модель `all-mpnet-base-v2`. Повторные запуски — секунды.

Внутри контейнера `docker-entrypoint.sh` поднимает uvicorn в фоне, ждёт его
health-check и запускает API в foreground.

### Проверка

```bash
curl http://localhost:5000/api/v1/health   # NCD: {"status":"ok",...}
curl http://localhost:5001/health          # API: {"status":"ok",...}
```

Открой http://localhost:5001/ — есть веб-дашборд.

### Полный цикл анализа

```bash
# Забрать статьи из RSS/NVD -> отправить в NCD -> сохранить концепты
curl -X POST "http://localhost:5001/api/v1/analyze/fetch-and-analyze?source=rss"

# Концепты
curl http://localhost:5001/api/v1/concepts?limit=50

# LLM-сводка по концептам
curl -X POST http://localhost:5001/api/v1/analyze/summarize \
     -H "Content-Type: application/json" \
     -d '{"concepts":[{"label":"Ransomware hits hospitals","strength":0.9,"documentCount":3,"sentences":["..."]}]}'
```

### Останов

```bash
docker compose down          # остановить
docker compose down -v       # остановить + стереть БД (/data/threats.db)
```

## Запуск без Docker (нативно)

Рабочее окружение — на `uv` (https://docs.astral.sh/uv). Модели качаются отдельно — см. следующий раздел.

### 0. Окружение (uv)

```bash
cd ncdbody
uv venv --python 3.12
uv pip install -r requirements.txt

# LLM-слой (опционально, только Apple Silicon):
uv pip install mlx mlx-lm
```

### 1. NCD (Python)

```bash
cd ncdbody
source .venv/bin/activate

# важно: одинарный поток numba (иначе сегфолт UMAP на arm64)
NUMBA_NUM_THREADS=1 NCD_DEVICE=cpu \
  uv run python -m uvicorn app.main:app --host 0.0.0.0 --port 5000
```

### 2. API (.NET 10)

```bash
cd ThreatDetector/src/ThreatDetector.Api
NcdService__Url=http://localhost:5000 \
  dotnet run --project . --urls http://0.0.0.0:5001
```

## Локальная разработка: скачивание моделей

Для полного функционала нужны 2 веса. Эмбеддер качается автоматически,
Granite-LM — вручную (лицензия IBM).

| Модель | Роль | Источник | Куда кладётся | Размер |
|--------|------|----------|---------------|--------|
| `sentence-transformers/all-mpnet-base-v2` | эмбеддинги текста | HuggingFace (публичный) | `~/.ncd/models` — авто | ~420 МБ |
| `granite-4.0-1b-mlx-4bit` | LLM: structured-экстракция + дайджесты | HuggingFace (gated) | `ncdbody/models/granite-4.0-1b-mlx-4bit` | ~883 МБ |

### 1. Эмбеддер (скачивается сам)

При первом старте NCD сам тянет модель с HuggingFace в кеш
`~/.ncd/models` (`NCD_MODEL_CACHE`). Можно предзагрузить заранее:

```bash
cd ncdbody
uv run python -c "
from app.config import NcdConfig
from sentence_transformers import SentenceTransformer
SentenceTransformer(NcdConfig.EMBEDDING_MODEL, cache_folder=NcdConfig.MODEL_CACHE_DIR)
print('OK ->', NcdConfig.MODEL_CACHE_DIR)
"
```

`uv pip install -r requirements.txt` потянет и torch (~2 ГБ) — это ожидаемо,
только подожди.

### 2. LLM Granite (MLX, только Apple Silicon)

Granite 4.0 на HuggingFace — **gated**: сначала на странице модели прими
лицензию IBM, затем:

```bash
cd ncdbody

# MLX-рантайм (без него LLM-слой молча отключается)
uv pip install mlx mlx-lm

# токен для HF (https://huggingface.co/settings/tokens)
huggingface-cli login

# сама модель (~883 МБ)
uv run huggingface-cli download ibm-granite/granite-4.0-1b-mlx-4bit \
  --local-dir models/granite-4.0-1b-mlx-4bit
```

Ожидаемые файлы в `ncdbody/models/granite-4.0-1b-mlx-4bit/`:
`config.json`, `model.safetensors` (~900 МБ), `tokenizer.json`, `chat_template.jinja`.

Папка по умолчанию совпадает с `NCD_LLM_MODEL` (`ncdbody/models/granite-4.0-1b-mlx-4bit`).
Если положил веса в другое место — укажи путь явно:

```bash
export NCD_LLM_MODEL=/полный/путь/до/granite-4.0-1b-mlx-4bit
```

### 3. Проверка LLM

Запусти NCD нативно и дёрни `/summarize`:

```bash
curl -s -X POST http://localhost:5000/api/v1/summarize -H "Content-Type: application/json" \
  -d '{"concepts":[{"label":"Ransomware hits hospital","strength":0.9,"documentCount":3,"sentences":["LockBit demands bitcoin","Patient records exfiltrated"]}]}'
```

Ожидаемый ответ: `"structured": true, "fallback": false`. Если `"fallback": true` —
модель не загрузилась: нет `mlx-lm`, неверный путь, не принята лицензия/токен.

### 4. Docker: включить LLM в образе

Контейнер собирается **без** весов (они в `.gitignore` и `.dockerignore`).
Чтобы включить LLM в compose: добавить `mlx`+`mlx-lm` в образ, смонтировать
папку с моделями и выставить env:

```yaml
services:
  concepta:
    volumes:
      - ./ncdbody/models:/app/ncdbody/models:ro
    environment:
      - NCD_LLM_MODEL=/app/ncdbody/models/granite-4.0-1b-mlx-4bit
```

### 5. Что теряется без LLM

`/summarize` вернёт `"fallback": true` — детерминированная ветка
(IOC-извлечение, severity-эвристика, MITRE) без LLM-дайджестов. Конкретных
описаний «что происходит» в дайджесте не будет, только статистика.

## NVIDIA (CUDA)

Fit the same models work on NVIDIA GPUs: MLX-вариант заменяется оригинальной
HF-моделью, генерация идёт через Hugging Face Transformers (+torch CUDA).

**Backend выбирается автоматически** (`auto`): если виден CUDA — `transformers`,
иначе на Apple Silicon — `mlx`. Есть явный `NCD_LLM_BACKEND` (mlx/transformers/none).

### 1. Установка (NVIDIA)

```bash
cd ncdbody
uv venv --python 3.12
uv pip install -r requirements.txt

# torch с CUDA (на Linux pip-версия уже с CUDA; здесь явно для контроля):
uv pip install torch --index-url https://download.pytorch.org/whl/cu128
```

### 2. Модель (не MLX, а bf16-оригинал)

`ibm-granite/granite-4.0-1b` — тоже gated: принять лицензию IBM на странице
модели, `huggingface-cli login`, затем:

```bash
uv run huggingface-cli download ibm-granite/granite-4.0-1b \
  --local-dir models/granite-4.0-1b
```

### 3. Запуск

```bash
export NCD_LLM_MODEL=/полный/путь/до/granite-4.0-1b     # или default ncdbody/models/granite-4.0-1b
export NCD_LLM_BACKEND=transformers
export NCD_LLM_DEVICE=cuda                               # cuda:0 / auto необязательны
# NCD_LLM_DTYPE=auto -> bfloat16 на Ampere+, float16 на старых GPU (можно переопределить)
```

Проверка — как в разделе для Apple Silicon (`/summarize`, ждём `"structured": true`).
В ответе `"model"` будет `granite-4.0-1b (HF Transformers)`.

### 4. Docker с GPU

Нужен runtime NVIDIA (Ubuntu: `sudo apt install nvidia-container-toolkit && sudo systemctl restart docker`).

```yaml
services:
  concepta:
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
    volumes:
      - ./ncdbody/models:/app/ncdbody/models:ro
    environment:
      - NCD_LLM_MODEL=/app/ncdbody/models/granite-4.0-1b
      - NCD_LLM_BACKEND=transformers
      - NCD_LLM_DEVICE=cuda
```

Замечание: эмбеддер-кеш (`~/.ncd/models`) — отдельно от LLM; в образе он просто
качается при первом старте (`NCD_MODEL_CACHE` можно тоже переопределить).

## Полезные параметры NCD (env)

| Переменная | По умолчанию | Описание |
|------------|-------------|----------|
| `NCD_HEATMAP_BINS` | `400` | Разрешение heatmap |
| `NCD_CLUSTER_MODE` | `blob` | `blob` (жёсткая) или `gmm` (мягкая кластеризация) |
| `NCD_USE_DIFF` | `0` | Diff-heatmap вместо абсолютной |
| `NCD_NOVELTY_THRESHOLD` | `0.5` | Порог новизны для k-NN |
| `NCD_UMAP_REFIT_INTERVAL` | `5` | Переобучение UMAP каждые N периодов |
| `NUMBA_NUM_THREADS` | — | **1** — обязателен на Apple Silicon |
| `NCD_EMBEDDING_MODEL` | `sentence-transformers/all-mpnet-base-v2` | Эмбеддер текста (HF) |
| `NCD_MODEL_CACHE` | `~/.ncd/models` | Кеш эмбеддера/весов |
| `NCD_LLM_MODEL` | `ncdbody/models/granite-4.0-1b-mlx-4bit` | Путь к MLX-модели Granite (пусто = только heuristics) |
| `NCD_LLM_BACKEND` | `auto` | `mlx` (Apple) · `transformers` (CUDA/CPU) · `none` |
| `NCD_LLM_DEVICE` | `auto` | Для transformers: `cuda` / `cuda:0` / `cpu` |
| `NCD_LLM_DTYPE` | `auto` | Для transformers: `bfloat16` / `float16` / `float32` |

## Частые вопросы

**Почему Fetch & Analyze даёт те же периоды?**
Фиды (Krebs, Hacker News) обновляются редко. Повторный запуск в течение короткого
времени парсит те же статьи → тот же результат. Новые данные появятся после
публикаций или при `?source=nvd`.

**LLM не подгружается в Docker.**
Образ NCD собирается без весов Granite (`NCD_LLM_MODEL=""`). Саммаризация
работает в детерминистическом режиме (IOC-извлечение, severity, MITRE).
Вес модели Granite доступен только при скачивании отдельно.