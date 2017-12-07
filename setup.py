from setuptools import setup, find_packages

def readme():
    with open('README.md') as f:
        return f.read()

setup(
    name='wishful_module_wifi_poprow',
    version='0.1.0',
    packages=find_packages(),
    url='http://www.wishful-project.eu/software',
    license='',
    author='ANS',
    author_email='msegata@disi.unitn.it',
    description='WiSHFUL Poprow Modules',
    long_description='WiSHFUL Poprow Modules',
    keywords='wireless control',
    install_requires=['netifaces','scapy-python3','numpy', 'python-iptables', 'pyroute2']
)
