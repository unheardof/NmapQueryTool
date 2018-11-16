import setuptools

with open("README.md", "r") as fh:
	long_description = fh.read()

setuptools.setup(
	name="nmap_query_tool",
	version="0.0.1",
	author="Timothy Heard",
	description="A tool for parsing and dynamically querying nmap scan data",
	long_description=long_description,
	long_description_content_type="text/markdown",
	url="https://github.com/unheardof/NmapQueryTool",
	packages=setuptools.find_packages(),
	classifiers=[
		"Programming Language :: Python :: 3",
		"License :: OSI Approved :: Apache Software License",
		"Operating System :: OS Independent",
		"Environment :: Console",
	],
)
