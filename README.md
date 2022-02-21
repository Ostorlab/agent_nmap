
<h1 align="center">Agent Nmap</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_tsunami">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_Nmap is an agent responsible for network discovery and security auditing (wraps around the Nmap tool)._

---

<p align="center">
<img src="https://github.com/Ostorlab/agent_nmap/blob/main/images/logo.png" alt="agent-tsunami" />
</p>

This repository is an implementation of [Ostorlab Agent](https://pypi.org/project/ostorlab/) for [Nmap](https://nmap.org/) (the Network Mapper).

## Getting Started
To perform your first scan, simply run the following command.
`ostorlab scan run --install --agents agent/ostorlab/nmap ip 8.8.8.8`

This command will download and install `agent/ostorlab/nmap` and target the ip `8.8.8.8`.
For more information, please refer to the [Ostorlab Documentation](https://github.com/Ostorlab/ostorlab/blob/main/README.md)


## Usage

Agent Nmap can be installed directly from the ostorlab agent store or built from this repository.

 ### Install directly from ostorlab agent store

 `ostorlab agent install agent/ostorlab/nmap`

You can then run the agent with the following command:
`ostorlab scan run --agents agent/ostorlab/nmap ip 8.8.8.8`


### Build directly from the repository

 1. To build the nmap agent you need to have [ostorlab](https://pypi.org/project/ostorlab/) installed in your machine.  if you have already installed ostorlab, you can skip this step.

`pip3 install ostorlab`

 2. Clone this repository.

`git clone https://github.com/Ostorlab/agent_nmap.git && cd agent_nmap`

 3. Build the agent image using ostorlab cli.

 `ostortlab agent build --file=ostorlab.yaml`.
 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 4. Run the agent using on of the following commands:
	 * If you did not specify an organization when building the image: `ostorlab scan run --agents agent//nmap ip 8.8.8.8`
	 * If you specified an organization when building the image: `ostorlab scan run --agents agent/[ORGANIZATION]/nmap ip 8.8.8.8`


## License
[Apache](./LICENSE)

