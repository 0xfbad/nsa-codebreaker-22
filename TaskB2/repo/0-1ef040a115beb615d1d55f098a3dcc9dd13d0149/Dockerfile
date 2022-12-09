FROM python:3.10.5-buster AS base

ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

FROM base AS python-deps
# Install pipenv
RUN pip install pipenv

COPY Pipfile Pipfile.lock ./
RUN PIPENV_VENV_IN_PROJECT=1 pipenv install --deploy

FROM base AS runtime
EXPOSE 5000
COPY --from=python-deps /.venv /.venv
ENV PATH="/.venv/bin:$PATH"

VOLUME  [ "/opt/ransommethis", "/opt/keyMaster" ]

COPY app /app

CMD waitress-serve --port=5000 app.server:app

