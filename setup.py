from setuptools import setup, find_packages

setup(
    name='anz.ecasclient',
    version='0.9.2',
    author='Eau de Web',
    author_email='office@eaudeweb.ro',
    url='http://www.eaudeweb.ro',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'anz.casclient == 1.0.1',
    ]
)
