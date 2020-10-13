import random
import os

services_dir = "/home/users/sandeep/dac/dac/services/"

ops = ["&","|","& !", "| !"]

def generate_term(s,attr_list):
    term = ''
    num_attrs = random.randint(1,4)
    for x in range(num_attrs):
        attr = attr_list[random.randint(0,len(attr_list) - 1)]
        s.add(attr)
        term += attr 
        if (x != num_attrs - 1):
            term += " " + ops[random.randint(0,len(ops) - 1)] + " "
    print 'term = ' + term
    return "( " + term + " )"

def generate_sub_component(s):
    attr_list = []
    sub_component = ''
    for x in range(10):
        num_comp = random.randint(0,49)
        attr = "A" + str(num_comp)
        attr_list.append(attr)

    num_terms = random.randint(2,4)    
    for x in range(num_terms):
        sub_component = sub_component + \
                generate_term(s, attr_list)
        if (x != num_terms - 1):
            sub_component +=" " + ops[random.randint(0,len(ops) - 1)] + " "
    print 'sub_component = ' + sub_component    
    return "( " + sub_component + " )"

def generate_policy_component(s):
    component = ''
    num_comp = random.randint(3,5)
    print "num_comp = " , num_comp
    for x in range(num_comp):
        component = component + \
                generate_sub_component(s)
        if(x != num_comp - 1):
            component += " " + ops[random.randint(0,len(ops) - 1)] + " "
    return "( " + component + " )"

for indx in range(500):
    service = "service" + str(indx + 1);
    num_policies = random.randint(5,10)
    attribute_set = set()
    output = ''
    for x in range(num_policies):
        policy = generate_policy_component(attribute_set)
        num_services = random.randint(1,3)
        services = ''
        for y in range(num_services):
            service_id = random.randint(0,499)
            services += "service" + str(service_id) + " "
        output  += policy + "\n" + services + "\n\n"

    try:
        os.mkdir(services_dir + service)
    except OSError:
        print ("Creation of the directory %s failed" % services_dir + service)
    else:
        print ("Successfully created the directory %s " % services_dir + service)     

    f = open(services_dir + service + "/policy.txt", "w");
    output = str(list(attribute_set)) + "\n" + str(num_policies) + "\n" + output
    f.write(output)
    f.close()
