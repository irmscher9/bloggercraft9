#!/bin/bash

echo "*** CREATING DATABASE!!! ***"

# create default database
psql -v ON_ERROR_STOP=1 --username "postgres" --dbname "testdb" <<-EOSQL
    CREATE SCHEMA tschema;
    CREATE TABLE tschema.test(firstname CHAR(15), lastname CHAR(20));
    INSERT INTO tschema.test values ('one', 'success');
EOSQL