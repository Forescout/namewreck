# Static analysis scripts for detecting NAME:WRECK issues

This repository contains a set of scripts for detecting [code
smells](https://en.wikipedia.org/wiki/Code_smell) that are relevant to some of
the [NAME:WRECK](http://todo) issues. 

These scripts use static analysis techniques against the source code, and they
have been implemented on top of the open-source code analysis platform
[Joern](https://joern.io/).

Currently, the script supports the following code smells:

* **Incorrect compression pointer checks**. A warning will be issued whenever a
statement that looks like a domain name compression pointer check that may violate [RFC
1035](https://tools.ietf.org/html/rfc1035) is detected.

* **Compression pointer offset computation**. A warning will be issued whenever
a statement that looks like a domain name compression pointer offset computation is detected. The
values of these offsets are often not checked in the code, and the presence of
such statements may warrant a closer inspection.

* **Memory copy calls with unchecked size value derived from a (compressed)
domain name**. A warning will be issued whenever a "memcpy()" call with an unchecked size
parameter derived from the compression offset or a domain name length octet is
detected.

* **Unchecked usages (e.g., pointer dereference) of values derived from a
(compressed) domain name**. A warning will be issued whenever unchecked usages of a value derived from the
compression offset or a domain name length octet are detected (e.g., pointer
dereference, pointer copy operations, etc.).

NOTE: the notion of a code smell implies that they are not bugs per se, but
*may* indicate their likely presence. Therefore, the main purpose of this script
is to direct the attention of the developers/researchers to potentially
vulnerable code locations.

## Installation and dependencies

In order to be able to run the script, [Joern](https://joern.io/) must be
installed. Refer to the official [installation
instructions](https://docs.joern.io/installation)

## Usage 

There are multiple ways to perform static analysis with Joern scripts, we will
outline a step-by-step scenario using the [interactive
shell](https://docs.joern.io/shell) of Joern. For more information on how to use
Joern refer to the [official documentation](https://docs.joern.io/home).

### Start the Joern Shell and import your code 

First, change the current working directory to the root of this project, and
invoke the joern shell as follows:

```bash
$ cd /home/[...]/name-wreck-joern
$ joern

joern> 
```

Import your code into Joern (note, this may take some time depending on the size
of your project):

```bash

joern> importCode(inputPath="/home/path-to-your-project", projectName="my_project")
```

You can then check if your code has been imported into the Joern workspace:

```basn
joern> workspace

res0: workspacehandling.WorkspaceManager[JoernProject] =
_________________________________________________________________
| name       | overlays    | inputPath                  | open  |
|================================================================
| my_project | semanticcpg | /home/path-to-your-project | true  |

```

Note that the "open" status of a project must be set to "true" in order to be
able to perform the analysis on it. If the project was closed closed, you can
re-open it by issuing the following command:


```bash
joern> workspace.openProject("my_project")
```

### Run the analysis

To run the analysis, import the scripts (make sure sure you started the Joern
shell from the working directory of this script), and run them as follows:

```bash
joern> import $file.queries.main

...

joern> main.exec()
```

Alternatively, you can run the script as follows:

```bash
cpg.runScript("/home/[...]/name-wreck-joern/queries/main.sc")
```

The output of the script has the following format:


```bash

--------------------------------------------------------------------------------
WARNING: [text of a warning]
--------------------------------------------------------------------------------

[Explanation text] 

[Location of the offending statement]

[file]
 |
 -> [function]
     |
     -> [line number: statement]

```

