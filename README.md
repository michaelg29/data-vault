# data-vault
 Secure data storage application written in C.
 Follows [this playlist](https://www.youtube.com/playlist?list=PLysLvOneEETNeg2YqISscjqA4udYRuGDb) on YouTube

# Local building
To build the source code, run the following commands from this directory:
```
cd build
./build
```
This will generate the executable `bin/dv.exe`.

# Running
* Create the following environment variable, `DV_HOME`, with the value `C:\...\data-vault\bin`. Make sure this path contains the executable `dv.exe`.
## Commands
You can then open this application from anywhere using the command line.

* To open up a continuous terminal session, run the following command:
    * You can then run data commands when prompted. See [this section](#data-commands).
```
dv
```

* To create an account, run the following command:
    * You will then be prompted for a username and password for your account.
    * For `<DATA_COMMAND>`, see [this section](#data-commands).
```
dv createAct <DATA_COMMAND>
```

* To run a single command, while providing credentials, run the following command:
    * `<USERNAME>` is the username for an existing account.
    * `<PASSWORD_ENV_NAME>` is the name of an environment variable containing the password. This is recommended if the environment variable is for the local, current terminal session.
    * `<DATA_COMMAND>` is the data command, see [this section](#data-commands).
```
dv [-u <USERNAME>] [-penv <PASSWORD_ENV_NAME>] <DATA_COMMAND>
```

## Data commands
* `exit`: Quit the application.
* `cls` or `clear`: Clear the terminal screen.
* `debug`: Switch on debugging information.
* `logout`: Logout the current user.
* `log`: Print all the entries and categories for the current user.
* `print`: Print the encrypted and decrypted data file contents.
* `createAct`: Create an account. Prompted for username and password.
* `login`: Login to an existing account. Prompted for username and password.
* `create <entry>`: Create an entry.
* `get <entry> <category>`: Get the data for an entry under a category.
* `copy <entry> <category>`: Put the data for an entry under a category onto the clipboard.
* `del <entry> <category>`: Delete the data for an entry under a category.
* `set <entry> <category> [<data>]`: Set the data for an entry under a category. Prompted for data if not entered in the command.
