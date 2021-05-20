#!/usr/bin/env python

import sys
import os
import argparse

def write_csv(filename, nb_users):
	with open(filename, "w") as csv_file:
		csv_file.write("SEQUENTIAL\n")
		for x in xrange(nb_users):
			line = "{uname};localhost;[authentication username={uname} password={uname}];\n".format(uname=str(1000+x))
			csv_file.write(line)

def write_sql(filename, nb_users):
	with open(filename, "w") as sql_file:
		header = """CREATE DATABASE IF NOT EXISTS tests;
                    USE tests;
                    DROP TABLE IF EXISTS accounts;
                    CREATE TABLE accounts (user VARCHAR(20),password VARCHAR(20));"""
		sql_file.write(header)
		for x in xrange(nb_users):
			line = """INSERT into accounts (user, password) VALUES ("{uname}", "{uname}");\n""".format(uname=str(1000+x))
			sql_file.write(line)


def main(argv=None):
	if argv == None:
		argv = sys.argv

	argparser = argparse.ArgumentParser(description="Prepare load tests for Flexisip.")
	argparser.add_argument('-N', '--users', help="How many different users should be registering to flexisip", dest="users", default=5000)
	args, additional_args = argparser.parse_known_args()

	write_csv("users.csv", args.users)
	write_sql("users.sql", args.users)

if __name__ == '__main__':
	main()


