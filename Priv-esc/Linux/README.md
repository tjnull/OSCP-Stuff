# GTFOPlus

GTFOPlus is a helper script that relies on the GTFOBins repo to identify standard Linux binaries that could assist with privilege escalation.

Deploy a gtfo.sh script to enumerate these binaries on your target machine.

Example Usage:

    python3 gtfo.py -b awk -l shell          | Spawning a shell with awk
    python3 gtfo.py -b awk -l all            | Show all GTFO capabilities of awk
    python3 gtfo.py -b awk -l all --verbose  | Increase verbosity + ascii art

Using the gtfo.sh agent script:

    ./gtfo.sh > gtf.out                      | Run this on target machine.
    python3 gtfo.py -f gtf.out -l all        | Show all capabilities for all 
                                             | binaries gathered from gtfo.sh
## Setup

In the same directory as that you cloned this repo, clone the GTFOBins Repo.

    git clone https://github.com/GTFOBins/GTFOBins.github.io.git
    python3 -m pip install -r requirements.txt

## Requirements 

    python3
    pyyaml

TODO:

* Make gtf.out parser better. (Add parser for groups, perms, ownership etc.)
* Pull GTFO bin capabilities from the repo as well.
