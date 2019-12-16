import random

ops = ["&","|","!"]

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
    num_comp = random.randint(3,8)
    print "num_comp = " , num_comp
    for x in range(num_comp):
        component = component + \
                generate_sub_component()
        if(x != num_comp - 1):
            component += " " + ops[random.randint(0,len(ops) - 1)] + " "
    return "( " + component + " )"

print generate_policy_component()
