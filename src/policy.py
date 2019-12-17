import random
import os

services_dir = "/home/sandeep/dac/services"

ops = ["&","|","& !", "| !"]

def generate_term(attr_list):
    term = ''
    num_attrs = random.randint(1,4)
    for x in range(num_attrs):
        attr = attr_list[random.randint(0,len(attr_list) - 1)]
        term += attr 
        if (x != num_attrs - 1):
            term += " " + ops[random.randint(0,len(ops) - 1)] + " "
    print 'term = ' + term
    return "( " + term + " )"

def generate_sub_component():
    attr_list = []
    sub_component = ''
    for x in range(10):
        num_comp = random.randint(0,49)
        attr = "A" + str(num_comp)
        attr_list.append(attr)

    num_terms = random.randint(2,4)    
    for x in range(num_terms):
        sub_component = sub_component + \
                generate_term(attr_list)
        if (x != num_terms - 1):
            sub_component +=" " + ops[random.randint(0,len(ops) - 1)] + " "
    print 'sub_component = ' + sub_component    
    return "( " + sub_component + " )"

def generate_policy_component():
    component = ''
    num_comp = random.randint(3,5)
    print "num_comp = " , num_comp
    for x in range(num_comp):
        component = component + \
                generate_sub_component()
        if(x != num_comp - 1):
            component += " " + ops[random.randint(0,len(ops) - 1)] + " "
    return "( " + component + " )"

dir_list = [x[0] for x in os.walk(services_dir)]
for x in dir_list:
    if (x == services_dir):
        continue
    f = open(x + "/policy.txt", "w");
    num_policies = random.randint(5,10)
    for x in range(num_policies):
        policy = generate_policy_component()
        num_services = random.randint(1,3)
        services = ''
        for y in range(num_services):
            service_id = random.randint(0,49)
            services += "service" + str(service_id) + " "
        f.write(policy)
        f.write("\n\n")
        f.write(services)
        f.write("\n\n")
    f.close()
