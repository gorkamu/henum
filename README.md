[![forthebadge made-with-python](http://ForTheBadge.com/images/badges/made-with-python.svg)](https://www.python.org/)
<p align='center'>
  <a href=""><img src="https://img.shields.io/badge/Version-1.0.0-brightgreen.svg?style=style=flat-square" alt="version"></a>
  <a href=""><img src="https://img.shields.io/badge/python-2-orange.svg?style=style=flat-square" alt="Python Version"></a>  
  <a href=""><img src="https://img.shields.io/github/license/Naereen/StrapDown.js.svg" alt="License"></a>
</p>

## What does this tool do?
This terminal tool allows you to perform various types of scans over a hostname.
With the tool you can perform scans of technology used as network scans but the key point is in the CMS scans.

### What is a CMS?
> A content management system (CMS) manages the creation and modification of digital content. It typically supports multiple users in a collaborative environment. Some noteable examples are: *WordPress, Joomla, Drupal etc*.

## How to install it
To install henum scanner just type the following command:
```python
pip install -r requirements.txt
```
Wait until all the dependencies are downloaded and proceed with the point below.
(**PyV8 must be installed** to run)

### Dependencies
- [PyV8](https://github.com/okoye/PyV8)

Note for macos users: If you have problems installing PyV8 you can use PyV8-OS-X:
```python
pip install -e git://github.com/brokenseal/PyV8-OS-X#egg=pyv8
```

## Sites to tests
- WP -> https://www.toyota.com.br/
- Joomla -> https://launch.joomla.org/
- magento -> http://demo-acm-2.bird.eu/
- drupal -> https://www.drupal.org/

## References
- https://github.com/robwillisinfo/cms-detector.py/blob/master/cms-detector.py
- https://github.com/Tuhinshubhra/CMSeeK/blob/master/VersionDetect/dru.py
