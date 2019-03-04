from setuptools import setup

setup(name='ci_secrets',
      version='0.0.1',
      description='A secrets scanner for CI/CD.',
      author='Phillip Marlow',
      author_email='phillip@marlow1.com',
      packages=['ci_secrets'],
	  install_requires=["detect_secrets"])