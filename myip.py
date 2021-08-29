from subprocess import check_output

def myip():
    ip = str(check_output(["hostname", "-I"]))
    ip = ip.split()
    ip = ip[0]
    ip = ip[2:]
    return ip

if __name__=="__main__":
    myip()
