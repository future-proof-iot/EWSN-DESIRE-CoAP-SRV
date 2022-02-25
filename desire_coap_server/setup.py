import os

from setuptools import setup, find_packages
from desire_srv import VERSION, PACKAGE_NAME
import desire_srv

# Cannot create this list with pip.req.parse_requirements() because it requires
# the pwd module, which is Unix only.
def _read_requirements(file_name):
    """
    Returns list of required modules for 'install_requires' parameter. Assumes
    requirements file contains only module lines and comments.
    """
    requirements = []
    with open(os.path.join(file_name)) as f:
        for line in f:
            if not line.startswith('#'):
                requirements.append(line.strip())
    return requirements

INSTALL_REQUIREMENTS = _read_requirements('requirements.txt')
print(INSTALL_REQUIREMENTS)

# read the contents of your README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md')) as f:
    LONG_DESCRIPTION = f.read()

setup(
    name=PACKAGE_NAME,
    packages=find_packages(exclude=['tests', '*.tests', 'tests.*', '*.tests.*']),
    python_requires='>3.8',
    include_package_data=True,
    install_requires=INSTALL_REQUIREMENTS,
    version=VERSION,
    description='',
    long_description_content_type='text/markdown',
    long_description=LONG_DESCRIPTION,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.8',
        'Topic :: Français',
    ],
    entry_points={
        "console_scripts": [
            'desire-coap-server = desire_srv.main:main',
        ],
    },
)
