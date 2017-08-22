# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).


## [0.0.20] - 2017-08-22 
### Added
- use 'us-east-1' in acm certificate lookup for yugen (#367)

### [0.0.19] - 2017-08-10
#### Added
- acm certificate lookup (#359) 
### Deprecated
- baseami lookup, use secret lookup instead

### [0.0.18] - 2017-07-18
### Deprecated
- kumo cloudformation config section, use "parameters" & "stack" instead (#337)

### [0.0.17] - 2017-06-29
#### Added
- included changelog in sre-docs
- prepare to handle signals in gcdt (#40)

### [0.0.13] - 2017-06-09
#### Added
- added capability to lookup the whole stack_output

### [0.0.10] - 2017-03-27
#### Changed
- moved plugins to separate repos and packages
