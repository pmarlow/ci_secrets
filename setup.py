from setuptools import setup

setup(name='ci_secrets',
      version='0.0.2',
      description='A secrets scanner for CI/CD.',
      author='Phillip Marlow',
      author_email='phillip@marlow1.com',
      packages=['ci_secrets'],
	  install_requires=["gitpython","detect_secrets"],
	  entry_points={
		'console_scripts': [
            'ci_secrets = ci_secrets:main'
        ]
	  })