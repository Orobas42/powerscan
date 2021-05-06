from __future__ import absolute_import
import setuptools

with open("require.cfg") as req:
    install_requires = [line.strip() for line in req if line.strip()]

setuptools.setup(
    name="powerscan",
    version="0.1",
    author="vP3nguin",
    author_email="leon@vp3ngu.in",
    url="https://github.com/vP3nguin/powerscan",
    keywords=["ip", "subnet", "scan", "ddos", "amplification", "brute-force"],
    include_package_data=True,
    packages=setuptools.find_packages(),
    install_requires=install_requires,
    entry_points={
        "console_scripts": [
            "powerscan=powerscan.scan:init",
        ],
    }
)
