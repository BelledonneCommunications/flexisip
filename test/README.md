
This file describes how to manage the tester scripts located in flexisip/test directory.

# Typical test

First, let's see what the typical layout should be for a test:

```
├── test                   # the test has its own directory
│   ├── flexisip.conf      # (mandatory) the flexisip.conf file that will be loaded by flexisip for this test
│   ├── invite-auth.xml    # the SIPP scenario that will be played when flexisip is running with authentication enabled
│   ├── invite.xml         # (mandatory) the SIPP scenario that will be played when flexisip is running without auth
│   ├── launch.config      # (mandatory) in this file we can tune some parameters that the main launch script uses, and perform launch preparation commands
│   ├── passwords          # (optional) test-specific password file for flexisip to use when authentication is enabled 
│   ├── uas.xml            # (optional) test-specific uas.xml. This is useful in case of non-INVITE-based tests. 
│   └── users.csv          # (optional) test-specific users authentication CSV
```

The tests are manipulated by the `./launch` bash script at the root of this directory. It takes 1 or 2 arguments: the folder of the test to conduct, and an optional 2nd argument which tells the tester to use authentication:

    ./launch registers/ # no auth
    ./launch registers/ TOTO # will enable auth, argument can be anything


# Operating

A typical test consists of 5 different processes:

- First, we start a SIPP process in background with the `uas.xml` scenario that is present at the root of the directory (or the one in the current test directory). This SIPP will listen on port 5063 for incoming INVITE (or other messages depending on test) when a test is running. It is running in background, so that it can survive for the duration of the test. All other SIPP processes will use the "Contact:" field to tell Flexisip to route INVITEs and other messages to this SIPP instance on port 5063.

- Then, we start flexisip with the appropriate configuration file. If the launch script is started with a 2nd argument, we enable authentication and use the `passwords` file as a user database. Flexisip is launched to listen on the port 50060 so as to not interfere with currently running flexisip on the same machine.

- Following that, we launch successively 2 SIPP processes that register the users that will be called, and another that will register the callers users. The scenarios in this case are stored in the root directory, and named `register_users[-auth].xml` and "register_inviter[-auth].xml". These two SIPP processes quit immediately after performing the registration, and they serve this purpose only.

- Finally, we launch the SIPP process that will play the `[test]/invite[-auth].xml` scenario that consists of the real test.

The launch script returns the last SIPP return value.

# A note on user names and passwords

SIPP provides an option to pass a CSV file, in which each line is a set of parameters for each play of the scenario. You will find that the `users.csv` file in the root directory is used to generate the password hash for the authenticated scenarios. This file is very small (2 lines) but has a header that tells SIPP how to infer all the users/password from it. See the SIPP documentation as to how this works: http://sipp.sourceforge.net/doc/reference.html#Injecting+values+from+an+external+CSV+during+calls

There exists a file in the base directory named `users.csv`, which is used as a base, but each test can provide its own users.csv. If there exists the users.csv file in the test directory, it will be used. Same applies for the `passwords` file.

# Configuring runtime parameters

You can override several parameters of execution using environment variables. Either setting them through a file named "launch.config.perso" located in the root directory (this file will be loaded before starting any process), or by specifying them on the command line:

    $ FLEXISIP=../src/flexisip ./launch mytest

They are listed here:

FLEXISIP    => path where to find the flexisip executable (default: /opt/belledonne-communications/bin/flexisip )
SIPP        => path where to find the sipp executable (default: sipp)

FLEXISIP_PORT => The port on which flexisip will bind to listen to incoming connections. This will also be the port which will be used for SIPP processes to connecte to the SIP server.
NB_USERS    =>

INV_RATE    => Number of invites to send every second when playing the test scenario

CALL_LENGTH =>

EXPIRE         => the expire to pass along when registering users. Make sure it is long enough to last the duration of your
SKIP_REGISTERS => You can skip the 2 sipp processes that register the users prior to running the test scenario by setting this variable to something not "0"