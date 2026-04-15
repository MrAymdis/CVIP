FROM python:3.11-slim

WORKDIR /app

COPY ./backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install requests

COPY ./backend/app/crawlers/nvd_monitor.py /app/app/crawlers/
COPY ./backend/app/crawlers/cvelistv5_crawler_v2.py /app/app/crawlers/
COPY ./backend/app/database.py /app/app/
COPY ./backend/app/models/ /app/app/models/
COPY ./backend/app/config.py /app/app/

CMD ["python", "/app/app/crawlers/nvd_monitor.py", "--continuous"]
