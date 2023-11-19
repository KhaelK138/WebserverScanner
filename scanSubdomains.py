import platform    # For getting the operating system name
import subprocess  # For executing a shell command
import socket      # For socketing to 80 and 443
import sys         # For reading arguments
import concurrent.futures # For multithreading

haveSubfinder = False
subfinderSubdomains = ""
subdirectoryDict = {}

# Reduce subdomain list to single copies of all subdomains (so we don't ping subdomains twice)
def reduceSubdomains(subdomainsToReduce):
    # Use this if we have subfinder subdomains
    reducedSubdomains = set()
    if haveSubfinder:
        addSubfinderDomains(reducedSubdomains)

    initialSubdomains = open(subdomainsToReduce, "r")
    for subdomain in initialSubdomains:
        # Extract subdomains from emails found
        if '@' in subdomain:
            subdomain = subdomain.split('@')[1]
    initialSubdomains.close()

    reducedSubdomainsFile = open("reducedSubdomains.txt", "w")
    for subdomain in reducedSubdomains:
            reducedSubdomainsFile.write(subdomain.strip() + '\n')
    reducedSubdomainsFile.close()
    return reducedSubdomains

def addSubfinderDomains(reducedSubdomains):
    subfinderSubdomainsFile = open(subfinderSubdomains, "r")
    for subfinderSubdomain in subfinderSubdomainsFile:
        if '/' in subfinderSubdomain:
            split = subfinderSubdomain.split('/')
            subdirectoryDict.update({split[0]:"/" + "/".join(split[1:]).strip()})
            subfinderSubdomain = split[0]
        reducedSubdomains.add(subfinderSubdomain.strip())
    if "" in reducedSubdomains:
        reducedSubdomains.remove("")

def aliveSubdomains(fullSubdomainSet):
    fullSubdomainSetLen = len(fullSubdomainSet)
    aliveSubdomains = set()
    i = 0
    print("Beginning Ping Scan\n---")
    for subdomain in fullSubdomainSet:
        
        fivePercent = fullSubdomainSetLen // 20
        if fivePercent > 0 and i % fivePercent == 0:
            percentage = int(i * 100.0 / fullSubdomainSetLen)
            print(f"{percentage}% Finished")
        if ping(subdomain.strip()):
            aliveSubdomains.add(subdomain)
        i += 1
    print(f"100% Finished\n---\n")
    return aliveSubdomains

def ping(host):
    param = '-n' if platform.system().lower()=='windows' else '-c'
    command = ['ping', param, '1', '-w', '300', host]
    return subprocess.call(command, stdout=subprocess.DEVNULL) == 0

def webserverSubdomains(aliveSubdomains):
    webserverSubdomains = set()
    aliveSubdomainSetLen = len(aliveSubdomains)
    i = 0
    print("Beginning Webserver Scan\n---")
    def check_web_server(subdomain):
        nonlocal i
        if check_port(subdomain.strip()):
            webserverSubdomains.add(subdomain)
        i += 1
        five_percent = aliveSubdomainSetLen // 20
        if five_percent > 0 and i % five_percent == 0:
            percentage = int(i * 100.0 / aliveSubdomainSetLen)
            print(f"{percentage}% Finished")

    max_workers = 20
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(check_web_server, aliveSubdomains)

    print(f"100% Finished\n---\n")
    return webserverSubdomains

def check_port(subdomain):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        result1 = sock.connect_ex((subdomain, 80))
        result2 = sock.connect_ex((subdomain, 443))
    except:
        return False
    return (result1 == 0 or result2 == 0)

def alphabetizeAndWriteAlive(webserverSubdomains):
    # Remove double instances of www
    cleanedWebserverSubdomains = webserverSubdomains.copy()
    for subdomain in webserverSubdomains:
        if subdomain[0:4] == "www." and subdomain[4:] in webserverSubdomains:
            cleanedWebserverSubdomains.remove(subdomain)

    sortedwebserverSubdomains = open("sortedWebserverSubdomains.txt", "w")
    for subdomain in sorted(cleanedWebserverSubdomains):
        if subdomain in subdirectoryDict.keys():
            sortedwebserverSubdomains.write(subdomain.strip() + subdirectoryDict.get(subdomain) + '\n')
        else:
            sortedwebserverSubdomains.write(subdomain.strip() + '\n')
    sortedwebserverSubdomains.close()

if __name__ == "__main__": 
    
    # Use first argument as entire subdomain list
    if len(sys.argv) > 1:
        subdomainsToReduce = str(sys.argv[1])
    else: 
        print("Please provide a list of domains to reduce as your first argument\n")
        exit(1)
    
    # Use second argument as subfinder subdomains
    if len(sys.argv) > 2:
        subfinderSubdomains = str(sys.argv[2])
        haveSubfinder = True
    else:
        print("If you have a list of subfinder subdomains, provide the name of the file as your second argument\n")

    # Reduce the subdomains to a set of unique subdomains
    reducedSubdomains = reduceSubdomains(subdomainsToReduce)

    # Ping subdomains - not necessary, as subdomains with webservers don't have to respond to pings
    # aliveSubdomains = aliveSubdomains(reducedSubdomains)

    # Check which alive subdomains host a webserver
    webserverSubdomains = webserverSubdomains(reducedSubdomains)

    # Organize webserverSubdomains alphabetically
    alphabetizeAndWriteAlive(webserverSubdomains)

    print("Alive webservers now in sortedWebserverSubdomains.txt\n")
    
