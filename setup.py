from setuptools import find_packages, setup

setup(
    name="step-ca-inspector-client",
    description="Step CA Inspector Client",
    author="Benjamin Collet",
    author_email="benjamin@collet.eu",
    packages=find_packages(),
    #long_description=open("README.md").read(),
    #long_description_content_type="text/markdown",
    install_requires=["requests>=2.20.0,<3.0", "PyYAML", "tabulate"],
    keywords=["step-ca-inspector"],
    version="0.0.2",
    classifiers=[
        "Intended Audience :: Developers",
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3",
    ],
    entry_points={
        "console_scripts": [
            "step-ca-inspector = step_ca_inspector_client.cli:main",
        ],
    },
)
