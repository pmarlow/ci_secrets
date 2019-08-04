from setuptools import setup

setup(name='ci_secrets',
      version='1.0.0',
      description='A secrets scanner for CI/CD.',
      author='Phillip Marlow',
      author_email='phillip@marlow1.com',
	  url="https://github.com/pmarlow/ci_secrets",
      packages=['ci_secrets'],
	  install_requires=["gitpython","detect_secrets"],
	  entry_points={
		'console_scripts': [
            'ci_secrets = ci_secrets:main'
        ]
	  },
	  classifiers=[
		"License :: OSI Approved :: Apache Software License",
		"Programming Language :: Python :: 3",
		"Topic :: Security",
		"Topic :: Software Development"
	  ])