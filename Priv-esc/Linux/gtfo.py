import argparse, os, sys, textwrap, yaml
splash = """
        ▄▄▄▄▄▄▄ ▄▄▄ ▄ ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄ ▄▄▄▄ ▄ ▄▄▄▄   ▄ ▄▄▄▄▄▄▄       
      ▄  ▄▄ ░ ▀▀ ██▄▄▄▄  ▄▄ ░  ▄▄   ██  ▄▄   ██ ██      ▄▄   ██ ▄▄ ░ ▀▀  ▄   
   ▀▀▀█  ██ ▀▀██ ██ ▒ ▄▄ ██▀▀  ██ ▒ ██  ██ ▀▀▀  ██ ▒ ██ ██ ▒ ██ ▀▀▀▀▀██  █▀▀▀
         ██▄▄▄█ ▄██▄▄▄██ ██ ░  ▀█▄▄▄█▀  ██ ░    ▄▄▄▄▄██ ▀█▄▄▄█▀ ██▄▄▄█▀  v0.1     
"""
parser = argparse.ArgumentParser(description='GTFO+')
parser.add_argument('-b', dest='bin',help='GTFO Bin')
parser.add_argument('-l', dest='list',help='Capabilities to List')
parser.add_argument('-f', dest='file',help='Read bins from file')
parser.add_argument("--quiet", dest='quiet',help="Decreate Output Verbosity",action="store_true")
parser.add_argument("--verbose", dest='verbose',help="increase output verbosity",action="store_true")
args = parser.parse_args()
binName  = args.bin
listWhat = args.list
infile   = args.file
quietout = args.quiet
verbose  = args.verbose

usage = """
gtfo.py is a helper for identifying standard Linux binaries that could assist 
with privilege escalation.
Deploy a gtfo.sh script to enumerate these binaries on your target machine.

Example Usage:

  python3 gtfo.py -b awk -l shell          | Spawning a shell with awk
  python3 gtfo.py -b awk -l all            | Show all GTFO capabilities of awk
  python3 gtfo.py -b awk -l all --verbose  | Increase verbosity + ascii art
  python3 gtfo.py -f gtf.out -l all        | Show all capabilities for all 
                                           | binaries gathered from gtfo.sh
"""

gtfoPath = 'GTFOBins.github.io/_gtfobins/'

listCommands = [ "all","bind-shell","capabilities","command","file-download","file-read","file-upload","file-write","library-load","limited-suid","non-interactive-bind-shell","non-interactive-reverse-shell","reverse-shell","shell","sudo","suid" ]

def loadBin(binFile):
  with open(binFile,'r') as stream:
    try:
      cleaned = stream.readlines()
      cleaned = cleaned[:-1]
      cleaned = ''.join(cleaned)
      data    = yaml.load(cleaned)
    except yaml.YAMLError as exc:
      print(exc)
  return data

gtfoInfo = {
  "bind-shell": {
    "name": "Bind shell",
    "desc": "It can bind a shell to a local port to allow remote network access."
  },
  "capabilities": {
    "name": "Capabilities",
    "desc": "It can manipulate its process UID and can be used on Linux as a backdoor to maintain elevated privileges with the CAP_SETUID capability set. This also works when executed by another binary with the capability set."
  },
  "command": {
    "name": "Command",
    "desc": "It can be used to break out from restricted environments by running non-interactive system commands."
  },
  "file-download": {
    "name": "File download",
    "desc": "It can download remote files."
  },
  "file-read": {
    "name":"File read",
    "desc":"It reads data from files, it may be used to do privileged reads or disclose files outside a restricted file system."
  },
  "file-upload": {
    "name": "File upload",
    "desc": "It can exfiltrate files on the network."
  },
  "file-write": {
    "name": "File write",
    "desc": "It writes data to files, it may be used to do privileged writes or write files outside a restricted file system."
  },
  "library-load": {
    "name": "Library load",
    "desc": "It loads shared libraries that may be used to run code in the binary execution context."
  },
  "limited-suid": {
    "name": "Limited SUID",
    "desc": "It runs with the SUID bit set and may be exploited to access the file system, escalate or maintain access with elevated privileges working as a SUID backdoor. If it is used to run commands it only works on systems like Debian that allow the default sh shell to run with SUID privileges."
  },
  "non-interactive-bind-shell": {
    "name": "Non-interactive bind shell",
    "desc": "It can bind a non-interactive shell to a local port to allow remote network access."
  },
  "non-interactive-reverse-shell":  {
    "name": "Non-interactive reverse shell",
    "desc": "It can send back a non-interactive reverse shell to a listening attacker to open a remote network access."
  },
  "reverse-shell": {
    "name": "Reverse shell",
    "desc": "It can send back a reverse shell to a listening attacker to open a remote network access."
  },
  "shell": {
    "name": "Shell",
    "desc": "It can be used to break out from restricted environments by spawning an interactive system shell."
  },
  "sudo": {
    "name": "Sudo",
    "desc": "It runs in privileged context and may be used to access the file system, escalate or maintain access with elevated privileges if enabled on sudo."
  },
  "suid": {
    "name": "SUID",
    "desc": "It runs with the SUID bit set and may be exploited to access the file system, escalate or maintain access with elevated privileges working as a SUID backdoor. If it is used to run sh -p, omit the -p argument on systems like Debian that allow the default sh shell to run with SUID privileges."
  }
}

print(splash)

def getBinInfo(qBin):
  binTitle = "───[ {} ]".format(binName)
  titleFill = "─"*(80-(len(binName)+7))
  print(binTitle+titleFill)
  try:
    print("  "+"\n".join(textwrap.wrap(qBin["description"], 75)))
  except KeyError:
    print(" ")
  binProp = qBin["functions"]
  if listWhat == "all":
    for gbin in binProp:
      gtfoDesc = gtfoInfo[gbin]["desc"]               # from local
      binCMD   = binProp[gbin][0]["code"].split("\n") # from file
      print("┌─ {}".format(gbin))                     
      print("│  "+"\n│  ".join(textwrap.wrap(gtfoDesc, 75)))
      print("└─ Usage:\n")
      for cmd in binCMD:
        if cmd == "": 
          pass 
        else:
          print("     {}".format(cmd))
      print(" ")
  else:
    gbin = listWhat
    try:
      gtfoDesc = gtfoInfo[gbin]["desc"]               #from local
      binCMD   = binProp[gbin][0]["code"].split("\n") # from file
      print("┌─ {}".format(gbin)) # was gtfoName
      print("│  "+"\n│  ".join(textwrap.wrap(gtfoDesc, 75)))
      print("└─ Usage:\n")
      for cmd in binCMD:
        if cmd == "": 
          pass 
        else:
          print("     {}".format(cmd))
      print(" ")
    except:
      pass

def quietBinInfo(qBin):
  padding = " "*(round((80-len(binName))))  # To right align bin names 
  print("{}{}".format(padding,binName))     # that makes it easier to
  print("{}{}".format(padding,'-'*len(binName))) # read :)
  binProp = qBin["functions"]
  if listWhat == "all":
    for gbin in binProp:
      binCMD   = binProp[gbin][0]["code"].split("\n")
      print("[{}]".format(gbin))                      
      for cmd in binCMD:
        if cmd == "": 
          pass 
        else:
          print("  {}".format(cmd))
      print(" ")
  else:
    gbin = listWhat
    try:
      binCMD   = binProp[gbin][0]["code"].split("\n")
      print("[{}]".format(gbin)) 
      for cmd in binCMD:
        if cmd == "": 
          pass 
        else:
          print("  {}".format(cmd))
      print(" ")
    except:
      pass

def getAvailableBins():
  filez = os.listdir(gtfoPath)
  availableBins = []
  for f in filez:
    if f[0] == ".":
      pass
    else:
      bb = f.split(".md")[0]
      availableBins.append(bb)
  return availableBins

def parseInfile(inputFile):
  with open(inputFile) as f:
    binz = []
    binListing = f.readlines()
    for b in binListing: # clean this ish up
      b = b.split(" ")
      p = b[-1:]         # Skipping over groups for now
      p = p[0].split("\n")[0]
      p = p.split("/")[-1:]
      binz.append(p[0])
    return binz

def showCapabilities():
  for i in range(0,len(listCommands)):
    print("  " + listCommands[i])

# Main functionality
try:
  # IF we are processing a gtfo.sh agent output
  if infile:
    binz = parseInfile(infile) # Should create an object of the bins in the file output
    binsAvailable = getAvailableBins()
    print("[!] Listing {} GTFO capabilities for {}\n".format(listWhat,infile))
    for b in binz:
      if b in binsAvailable:
        binArg    = b
        binName   = b
        binSelect = gtfoPath+binArg+".md"
        binInfo   = loadBin(binSelect)
        if verbose:
          getBinInfo(binInfo)
        else:
          quietBinInfo(binInfo)
  # Otherwise we are processing a single binary
  else:
    if listWhat not in listCommands:
      exit()
    binArg    = binName
    binSelect = gtfoPath+binArg+".md"
    binInfo   = loadBin(binSelect)
    print("[!] Listing {} GTFO capabilities for {}\n".format(listWhat,binArg))
    if verbose:
      getBinInfo(binInfo)
    else:
      quietBinInfo(binInfo)
except:
  print(usage)
  binsAvailable = getAvailableBins()
  print("[Available Binaries] Specify with the -b flag")
  for b in binsAvailable:
    if b == binsAvailable[-1]:
      print(b)
    else:
      print(b,end=', ')
  print("\n[Available Capabilities] Specify with the -l flag")
  showCapabilities()