# Nmap agent  
An implementation of [Osorlab Agent]((https://pypi.org/project/ostorlab/) for the [Nmap](https://nmap.org/).  

## Usage

Refer to Ostorlab documentation.

### Install directly from ostorlab agent store.

`ostorlab agent install agent/ostorlab/agent_nmap`

### Build directly from the repository

 1. To build the tsunami agent you need to have [ostorlab](https://pypi.org/project/ostorlab/) installed in your machine.  if you have already installed ostorlab you can skip this step.
 
`pip3 install ostorlab` 
 
 3. clone this repository.
 
`git clone https://github.com/Ostorlab/agent_nmap.git && cd agent_nmap`
   
 4. build the agent image using ostorlab cli.

 `ostortlab agent build --file=ostorlab.yaml`

