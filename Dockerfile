FROM python:3.10
ARG PACKAGE
COPY db/create.sql /docker-entrypoint-initdb.d/.
RUN apt-get clean && apt-get update && apt-get install -y postgresql postgresql-contrib
RUN apt-get install -y gcc
ENV DB_USER=default_user
ENV DB_PASSWORD=default_password
ENV DB_NAME=default_db
USER postgres
RUN /etc/init.d/postgresql start && \
    psql --command "CREATE USER ${DB_USER} WITH SUPERUSER PASSWORD '${DB_PASSWORD}';"
USER root
RUN pip install pip
RUN pip install psycopg2
WORKDIR /app
COPY . /app
COPY config.toml /app/src/bomsquad/vulndb/config.toml
COPY ${PACKAGE} /app
COPY pg_hba.conf /etc/postgresql/15/main/pg_hba.conf
RUN pip install -e .
USER postgres
RUN /etc/init.d/postgresql start && psql < /app/db/create.sql
RUN /etc/init.d/postgresql start && vulndb nvd ingest --scope cve
RUN /etc/init.d/postgresql start && vulndb osv ingest
EXPOSE 5000
ENTRYPOINT [ "/app/vulndb.sh" ]


