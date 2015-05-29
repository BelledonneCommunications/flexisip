#!/usr/bin/env python
# -*- coding: UTF-8 -*-

try:
    import sys
    import os
    import argparse
    import itertools
    import copy
    import mysql.connector
    import getpass
    from prettytable import PrettyTable
except:
    print("Please install python-mysql.connector python-prettytable")
    sys.exit(1)


def pretty_print_data_vertically(header, data):
    formatted = []
    max_field_width = max([len(x) for x in header])
    for row_i, row in enumerate(data):
        formatted.append(
            '*************************** %i. row ***************************' %
            (row_i + 1, ))
        for i, field in enumerate(header):
            formatted.append("%s: %s" % (field.rjust(max_field_width), row[i]))
    print('\n'.join(formatted))


def pretty_print_create_table(header, data, align_settings=None):
    x = PrettyTable(header)
    if align_settings is not None:
        for (key, val) in align_settings.items():
            x.align[key] = val
    for line in data:
        x.add_row(line)
    print(x)


def pretty_print_data(header, data, align_settings=None, max_width=-1):
    if max_width == -1:
        # retrieve real width of terminal, if available
        try:
            rows, columns = os.popen('stty size', 'r').read().split()
            max_width = int(columns)
        except:
            max_width = 80

    current_width = 1
    start_ind = 0
    end_ind = 0

    if not data:
        print "No data to pretty print!"
        return

    while end_ind < len(header):
        # adding 4 constant for borders + gap spaces (like '| something |')
        max_cur_width = 3 + \
            max(len(header[end_ind]),
                max([len(str(row[end_ind])) for row in data]))

        if current_width + max_cur_width < max_width:
            current_width += max_cur_width
            end_ind += 1
            continue

        pretty_print_create_table(
            header[start_ind:end_ind],
            [row[start_ind:end_ind] for row in data], align_settings
        )
        start_ind = end_ind
        current_width = 1

    if start_ind != end_ind:
        pretty_print_create_table(
            header[start_ind:end_ind],
            [row[start_ind:end_ind] for row in data], align_settings
        )


def query_db(options, display=True):
    try:
        cnx = mysql.connector.connect(
            host=options.host, port=options.port, user=options.user,
            password=options.password, database=options.database_name)
    except mysql.connector.Error as e:
        err = "Could not connect to database {}: ".format(options.database_name)
        if e.errno == 1045:
            err += """either password is INCORRECT or {username} user is not authorized to access the database from current location.
To have access, you must create an user in the database using:
    create user '{username}'@'{your_ip}' IDENTIFIED BY 'THE_PASSWORD'
    grant all privileges on {db}.* to '{username}'@'{your_ip}' WITH GRANT OPTION;""".format(username=options.user, your_ip="YOUR_IP", db=options.database_name)
        else:
            err += str(e)
        print(err)
        sys.exit(3)

    try:
        cursor = cnx.cursor()
        output = []

        # display name of all tables
        if options.list_tables is True:
            query = ("SHOW tables")
            cursor.execute(query)
            output = cursor.fetchall()
            if display is True:
                pretty_print_data(["table"], output)

        # display fields of a given table
        elif options.show_table is not None:
            query = ("desc {}".format(options.show_table))
            cursor.execute(query)
            output = cursor.fetchall()
            if display is True:
                pretty_print_data(["field", "field_type"], output)

        # display all calls
        elif options.list_calls is True:
            query = ("SELECT dialog_id, lm_qe_moslq, "
                     "lm_qe_moscq, rm_qe_moslq, "
                     "rm_qe_moscq "
                     "FROM CallQualityStatisticsLog ")

            cursor.execute(query)
            output += cursor.fetchall()

            if display is True:
                pretty_print_data(
                    [
                        "dialog_id",
                        "local_moslq",
                        "local_moscq",
                        "remote_moslq",
                        "remote_mscq"
                    ],
                    output,
                    align_settings={"dialog_id": "l"}
                )

        # display calls with bad MOS values. Since both call ends can submit
        # reports, we use the local/remote distinction to detect which side
        # was poor quality
        elif options.bad_calls != -1:
            for mode in ['l', 'r']:
                query = ("SELECT dialog_id, \"{mode}\", {mode}m_qe_moslq, "
                         "{mode}m_qe_moscq, from_unixtime(lm_ts_start) "
                         "FROM CallQualityStatisticsLog "
                         "WHERE {mode}m_qe_moslq BETWEEN 0 AND {minval} "
                         "OR {mode}m_qe_moscq BETWEEN 0 AND {minval} "
                         "GROUP BY dialog_id "
                         "ORDER BY lm_ts_start")
                query = query.format(mode=mode, minval=options.bad_calls)

                cursor.execute(query)
                output += cursor.fetchall()

            if display is True:
                if output == []:
                    print("No call found with statement: 0 ≤ MOS value ≤ %f." %
                          options.bad_calls)
                else:
                    pretty_print_data(
                        ["dialog_id", "mode", "moslq", "moscq", "start_date"],
                        output,
                        align_settings={"dialog_id": "l"}
                    )

        # display all collected data for a given dialog_id. We do NOT use
        # call_id because both call ends can emit a quality report with the
        # same Call-ID. Since the dialog_id user the from-tag and to-tag which
        # are opposed between caller and callee, this ensure a unique report
        # sender
        elif options.show_call is not None:
            options_copy = copy.deepcopy(options)
            options_copy.show_table = "CallQualityStatisticsLog"
            options_copy.show_call = None

            # retrieve all fields but QOS related data which will be treated
            # after
            fields = [x[0] for x in query_db(
                options_copy, display=False) if not x[0].startswith('qos_')]

            query = ("SELECT {} "
                     "FROM CallQualityStatisticsLog "
                     "WHERE dialog_id LIKE \"%{}%\" "
                     .format(', '.join(fields), options.show_call)
                     )
            cursor.execute(query)
            output = cursor.fetchall()

            if output is None or output == []:
                print("Could not find call with dialog_id='{}'"
                      .format(options.show_call))
                return

            if display is True:
                pretty_print_data_vertically(fields, output)

            # then print(qos specific data)
            query = ("SELECT qos_name, qos_timestamp, qos_input_leg, "
                     "qos_input, qos_output_leg, qos_output, dialog_id "
                     "FROM CallQualityStatisticsLog "
                     "WHERE dialog_id LIKE \"%{}%\" "
                     .format(options.show_call)
                     )

            cursor.execute(query)
            results = cursor.fetchall()

            (qos_name, qos_timestamp, qos_input_leg, qos_input,
             qos_output_leg, qos_output, dialog_id) = results[0]

            # QOS specific section stores data as comma separated values for
            # each action it as done within the call
            header = None

            # there can be multiple lines matching a single dialog_id in case
            # of Interval reports
            output = []
            for line in results:
                (qos_name, qos_timestamp, qos_input_leg, qos_input,
                 qos_output_leg, qos_output, dialog_id) = line

                if header is None or header[2] == '':
                    header = [list(itertools.chain.from_iterable(x))
                              for x in [[
                                        ["ts"],
                                        qos_input_leg.split(' '),
                                        qos_output_leg.split(' '),
                                        ["dialog_id"]
                                        ]]
                              ][0]

                # if timestamps is empty, there is no valid data in this report
                if not qos_timestamp:
                    continue

                timestamp = qos_timestamp.split(';')[:-1]
                split_input = qos_input.split(';')[:-1]
                split_output = qos_output.split(';')[:-1]
                output += [list(itertools.chain.from_iterable(x))
                           for x in [
                                    [
                                        [int(timestamp[x])],
                                        split_input[x].split(' '),
                                        split_output[x].split(' '),
                                        [dialog_id]
                                    ] for x in range(len(timestamp))]
                           ]

            if output:
                start = min([x[0] for x in output])
                output = [[x[0] - start] + x[1:] for x in output]

                # sort array by timestamps value
                output.sort()

            if header[2] == '':
                print('This record has not QOS data report enabled.')
            else:
                # print pretty table, as any SGBD should
                if display is True:
                    pretty_print_data(
                        header, output, align_settings={"dialog_id": "l"})

    except mysql.connector.Error as e:
        print("Could not apply query: {}.".format(e))
        return None
    except Exception as e:
        print("Some exception occurred line {}: {}.".format(
            sys.exc_info()[-1].tb_lineno, e))
        return None
    finally:
        cursor.close()
        cnx.close()
        return output


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--database',
                        dest="database_name",
                        required=True,
                        help="database name"
                        )
    parser.add_argument('-H', '--host',
                        dest="host",
                        default="127.0.0.1",
                        help="database host IP/DNS location"
                        )
    parser.add_argument('-P', '--port',
                        dest="port",
                        default=3306,
                        type=int,
                        help="database host port"
                        )
    parser.add_argument('-u', '--user',
                        dest="user",
                        help="database user",
                        default="root"
                        )
    password_group = parser.add_mutually_exclusive_group(required=True)
    password_group.add_argument('-p', '--password',
                                dest="password",
                                help="database user password",
                                )
    password_group.add_argument('-ap', '--ask-password',
                                dest="ask_password",
                                help="ask for database user password",
                                action="store_true"
                                )

    query_group = parser.add_mutually_exclusive_group(required=True)
    query_group.add_argument('-L', '--list-tables',
                             dest="list_tables",
                             default=False,
                             action="store_true",
                             help="display list of database tables"
                             )
    query_group.add_argument('-t', '--show-table',
                             dest="show_table",
                             default=None,
                             help="display structure of the given table"
                             )
    query_group.add_argument('-C', '--list-calls',
                             dest="list_calls",
                             default=False,
                             action="store_true",
                             help="display list of calls"
                             )
    query_group.add_argument('-B', '--bad-calls',
                             dest="bad_calls",
                             default=-1,
                             type=float,
                             help="display calls'ID with a local and/or remote"
                             " MOSLQ/MOSCLQ lower than given value in [0, 5].",
                             metavar="MIN_MOS_VALUE"
                             )
    query_group.add_argument('-c', '--show-call',
                             dest="show_call",
                             default=None,
                             help="display quality data for a given call ID"
                             )

    options = parser.parse_args()
    if options.ask_password:
        options.password = getpass.getpass()

    query_db(options)

if __name__ == "__main__":
    main(sys.argv[1:])
