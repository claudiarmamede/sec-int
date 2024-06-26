# Linter to measure compliance aganst 

```
1   vuln-detect: <weakness> in <file:lines> (severity: <severity>)
2
3   [Summary explanation of the subject/header in ~75 words.]
4     What: Explain the security issue(s) that was detected.
5     Why:  Focus on why this vulnerability is relevant and potential impact.
6     How:  Describe how this vulnerability can be triggered.
7     When: Describe when the vulnerability was found (DD-MM-YYYY)   
8
9   [Vulnerability description]
10    Weakness: weakness identification or CWE-ID. 
11    Severity: severity of the issue (Low, Medium, High, Critical).
12    File: vulnerability location at file-level
13    Location: vulnerability location at function/module-level
14    Lines: vulnerable lines
15    Unchecked tainted variables: tainted variables that do not belong to any control structure 
16    Checked tainted variables: tainted variables that belong to a control structure 
17    Sources: all entry points in code where user input enters an application
18    Sinks: all actions performed by the application, using user input from a source
19    Extra: extra information useful to detect additional vulnerability typess
20
21  [Reporter info]
22    Reported-by: reporter name <reporter-email@host.com>
23    Method: description of the tools used (either manual, tool, AI)
24    
25  [If you use an issue tracker, add reference to it here. It includes github.]
26    Bug-tracker: https://link-to-bug-tracker/id
27    Issue: number of the issue  
28
```




# SECOMlint [![Build Status](https://app.travis-ci.com/TQRG/secomlint.svg?branch=main)](https://app.travis-ci.com/TQRG/secomlint)

Linter to measure compliance against [SECOM](https://tqrg.github.io/secom/) convention. SECOM is a convention for making security commit messages more readable and structured. Check the [CONFIG.md](https://github.com/TQRG/secom/blob/main/CONFIG.md) file to know how to configure the template in your repository.

<p align="center">
  <img width="600" src="assets/secomlint.svg">
</p>

## Installation

```
pip install secomlint
python -m spacy download en_core_web_lg
```

From the source code:
```
git clone https://github.com/TQRG/secomlint.git
cd secomlint
pip install .
python -m spacy download en_core_web_lg
```

## Usage

```
secomlint --help
```
```
Usage: secomlint [OPTIONS]

  Linter to check compliance against SECOM (https://tqrg.github.io/secom/).

Options:
  --no-compliance        Show missing compliance.
  --is-body-informative  Checks body for security information.
  --score                Show compliance score.
  --config TEXT          Rule configuration file path name.
  --help                 Show this message and exit.
```

## Run tool

`git log -1 --pretty=%B | secomlint` where `git log -1 --pretty=%B` gets the commit message of the local commit.

* Check only the rules that are not in compliance: `git log -1 --pretty=%B | secomlint --no-compliance`
* Calculate compliance score: `git log -1 --pretty=%B | secomlint --no-compliance --score`

<p align="center">
  <img width="600" src="assets/secomlint2.svg">
</p>


## Configuration

The linter has a default configuration that can be overridden with a `.yml` file using the following syntax: 

```
rule_name:
    active: {true | false}
    type: {0 - warning | 1 - error}
    value: {string | regex}
```

An example would be:

```
header_starts_with_type:
  active: true
  type: 0
  value: 'fix'
metadata_has_detection:
  active: false
```
(The rule `header_starts_with_type` is active, outputs warnings and checks if header starts with type fix. The rule `metadata_has_detection` was deactivated.)

```
git log -1 --pretty=%B | secomlint --config=config.yml
```

## Check if the message's body is informative enough

It is important that the body of security commit messages are somehow informative; SECOMlint checks the message's body for security-related keywords.

```
git log -1 --pretty=%B | secomlint --is-body-informative
```
```
👍 Good to go! Extractor found the following security related words in the message's body:
   - protocols
```