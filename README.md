
<h1 align="center">Agent Nmap</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_nmap">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_Nmap is an agent responsible for network discovery and security auditing (wraps around the Nmap tool)._

---

<p align="center">
<img src="https://github.com/Ostorlab/agent_nmap/blob/main/images/logo.png" alt="agent-nmap" />
</p>

This repository is an implementation of [OXO Agent](https://pypi.org/project/ostorlab/) for [Nmap](https://nmap.org/) (the Network Mapper).

## Getting Started
To perform your first scan, simply run the following command.
```shell
oxo scan run --install --agent agent/ostorlab/nmap ip 8.8.8.8
```

This command will download and install `agent/ostorlab/nmap` and target the ip `8.8.8.8`.
For more information, please refer to the [OXO Documentation](https://oxo.ostorlab.co/docs)


## Usage

Agent Nmap can be installed directly from the oxo agent store or built from this repository.

Supported agent flags:

* `fast_mode` (`-F`): Fast mode scans fewer ports than the default mode.
* `ports` (`-p`): List of ports to scan.
* `top_ports` (`--top-ports`): Top ports to scan.
* `no_ping` (`-Pn`): Treat all hosts as online, skip host discovery.
* `version_info` (`-sV`): Probe open ports to determine service/version info.
* `timing_template` (`-Tx`): Template of timing settings (T0, T1, ... T5)..
* `script_default` (`-sC`): Script scan, equivalent to --script=default.
* `scripts` (`--script`): List of scripts to run using Nmap.
* `os` (`--os`): Enable OS detection.
* `decoys` (`-R RND:<number of decoys>`): Makes it seem like decoy hosts are also scanning the target network.
* `firewall_evasion` : Makes the scan quieter and less noticeable, helping it slip past firewalls.

 ### Install directly from OXO agent store

 ```shell
 oxo agent install agent/ostorlab/nmap
 ```

You can then run the agent with the following command:
`oxo scan run --agent agent/ostorlab/nmap ip 8.8.8.8`


### Build directly from the repository

 1. To build the nmap agent you need to have [oxo](https://pypi.org/project/ostorlab/) installed in your machine. If you have already installed oxo, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone https://github.com/Ostorlab/agent_nmap.git && cd agent_nmap
```

 3. Build the agent image using oxo cli.

 ```shell
 oxo agent build --file=ostorlab.yaml
 ```
 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 4. Run the agent using on of the following commands:
	 * If you did not specify an organization when building the image:
	  ```shell
	  oxo scan run --agent agent//nmap ip 8.8.8.8
	  ```
	 * If you specified an organization when building the image:
	  ```shell
	  oxo scan run --agent agent/[ORGANIZATION]/nmap ip 8.8.8.8
	  ```


## License
[Apache](./LICENSE)

