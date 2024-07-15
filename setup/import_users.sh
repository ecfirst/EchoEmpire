#!/bin/bash

# Variables
DB_USER="empire_user"
DB_PASSWORD="empire_password"
DB_NAME="empire"
TABLE_NAME="users"
CSV_FILE="/tmp/users_table.csv"

# Import the data from CSV file into the MySQL table
mysql -u $DB_USER -p$DB_PASSWORD -e "USE $DB_NAME; \
LOAD DATA INFILE '$CSV_FILE' \
INTO TABLE $TABLE_NAME \
FIELDS TERMINATED BY ',' ENCLOSED BY '\"' \
LINES TERMINATED BY '\n' \
IGNORE 1 LINES;"
