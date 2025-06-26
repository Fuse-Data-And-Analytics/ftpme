import setuptools

setuptools.setup(
    name="file_exchange",
    version="0.0.1",
    description="File Exchange Platform CDK",
    packages=setuptools.find_packages(),
    install_requires=[
        "aws-cdk-lib",
        "constructs"
    ],
)
