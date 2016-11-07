honeypot deploy script

Simple, works, a little dirty.

It
- Uses the api to deploy a linode
- Installs ubuntu 14.04
- Does basic initial configuration
- Inside a tmux session:
	- Installs a honeypot
	- Adds it to the pool

usage:python deploy.py [DCID] [Honeypot] [node label]

