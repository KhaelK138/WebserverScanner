import platform    # For getting the operating system name
import subprocess  # For executing a shell command
import socket      # For socketing to 80 and 443
import sys         # For reading arguments

haveSubfinder = False
subfinderSubdomains = ""

# Reduce subdomain list to single copies of all subdomains (so we don't ping subdomains twice)
def reduceSubdomains(subdomainsToReduce):
    reducedSubdomains = set()

    # Fill subdomains.txt with subdomains to test for socket
    initialSubdomains = open(subdomainsToReduce, "r")
    for subdomain in initialSubdomains:
        # extract subdomains from emails found
        if '@' in subdomain:
            subdomain = subdomain.split('@')[1]
        reducedSubdomains.add(subdomain)
    initialSubdomains.close()

    reducedSubdomainsFile = open("reducedSubdomains.txt", "w")
    for subdomain in reducedSubdomains:
            reducedSubdomainsFile.write(subdomain)
    reducedSubdomainsFile.close()
    return reducedSubdomains

def aliveSubdomains(reducedSubdomains):
    # Use this if we have subfinder subdomains
    fullSubdomainSet = reducedSubdomains
    if haveSubfinder:
        fullSubdomainSet = addSubfinderDomains(reducedSubdomains)
    
    fullSubdomainSetLen = len(fullSubdomainSet)
    aliveSubdomains = set()
    i = 0
    print("Beginning Ping Scan\n---")
    for subdomain in fullSubdomainSet:
        # print(subdomain)
        
        fivePercent = fullSubdomainSetLen // 20
        if fivePercent > 0 and i % fivePercent == 0:
            percentage = int(i * 100.0 / fullSubdomainSetLen)
            print(f"{percentage}% Finished")
        if ping(subdomain.strip()):
            aliveSubdomains.add(subdomain)
        i += 1
    print(f"100% Finished\n---\n")
    return aliveSubdomains

def addSubfinderDomains(reducedSubdomains):
    fullSubdomainSet = reducedSubdomains
    subfinderSubdomainsFile = open(subfinderSubdomains, "r")
    for subfinderDomain in subfinderSubdomainsFile:
        fullSubdomainSet.add(subfinderDomain)
    return fullSubdomainSet

def ping(host):
    param = '-n' if platform.system().lower()=='windows' else '-c'
    command = ['ping', param, '1', '-w', '300', host]
    return subprocess.call(command, stdout=subprocess.DEVNULL) == 0

def webserverSubdomains(aliveSubdomains):
    webserverSubdomains = set()
    aliveSubdomainSetLen = len(aliveSubdomains)
    i = 0
    print("Beginning Webserver Scan\n---")
    
    for subdomain in aliveSubdomains:
        # print(subdomain)
        
        fivePercent = aliveSubdomainSetLen // 20
        if fivePercent > 0 and i % fivePercent == 0:
            percentage = int(i * 100.0 / aliveSubdomainSetLen)
            print(f"{percentage}% Finished")
        if check_port(subdomain.strip()):
            webserverSubdomains.add(subdomain)
        i += 1
    print(f"100% Finished\n---\n")
    return webserverSubdomains

def check_port(domain):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        result1 = sock.connect_ex((domain, 80))
        result2 = sock.connect_ex((domain, 443))
    except:
        return False
    return (result1 == 0 or result2 == 0)

def alphabetizeAndWriteAlive(webserverSubdomains):
    sortedwebserverSubdomains = open("sortedWebserverSubdomains.txt", "w")
    for subdomain in sorted(webserverSubdomains):
        sortedwebserverSubdomains.write(subdomain.strip() + '\n')
    sortedwebserverSubdomains.close()

if __name__ == "__main__":  
    print()
    
    # Use first argument as entire subdomain list
    if sys.argv[1]:
        subdomainsToReduce = str(sys.argv[1])
    else: 
        print("Please provide a list of domains to reduce as your first argument\n")
    
    # Use second argument as subfinder subdomains
    if sys.argv[2]:
        subfinderSubdomains = str(sys.argv[2])
        haveSubfinder = True
    else:
        print(print("If you have a list of subfinder subdomains, provide the name of the file as your second argument\n"))

    # Reduce the subdomains to a set of unique subdomains
    reducedSubdomains = reduceSubdomains(subdomainsToReduce)

    # Find the alive subdomains
    aliveSubdomains = aliveSubdomains(reducedSubdomains)

    # Check which alive subdomains host a webserver
    webserverSubdomains = webserverSubdomains(aliveSubdomains)

    # Organize webserverSubdomains alphabetically
    alphabetizeAndWriteAlive(webserverSubdomains)

    print("Alive subdomains now in sortedWebserverSubdomains.txt\n")
    
