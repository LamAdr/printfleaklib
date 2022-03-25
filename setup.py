from setuptools import find_packages, setup

setup(
    name='printfleaklib',
    packages=['printfleaklib'],
    description='Manages printf format string leaks',
    install_requires=['pwn', 'prettytable'],
)
