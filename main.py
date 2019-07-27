def convert_str_int(ip_str):
    ip = ip_str.split('.')
    num = 0
    for i in range(0, 4):
        num = num * 256 + int(ip[i])
    return num


def convert_ace_data(ace):
    line = ace.strip(' \n\r')
    lines = line.split(' ')
    if lines[0] == 'permit' or lines[0] == 'deny':
        x = []
        i = 2
        while i < len(lines):
            if lines[i] == 'eq' or lines[i] == 'lt' or lines[i] == 'gt':
                i = i + 1
            elif lines[i] == 'range':
                i = i + 2
            elif lines[i] == 'any':
                x.extend([0, 0])
            elif lines[i] == 'host':
                i = i + 1
                x.extend([convert_str_int(lines[i]), 0xffffffff])
            else:
                x.extend([convert_str_int(lines[i]), 0xffffffff - convert_str_int(lines[i + 1])])
                i = i + 1

            i = i + 1
    else:
        x = ['', '', '', '']

    return {'raw': line, 'src': x[0], 'src_mask': x[1], 'dst': x[2], 'dst_mask': x[3]}

def cmp_data(model, ref):
    return ((model['src'] & ref['src_mask']) == ref['src']) and ((model['dst'] & ref['dst_mask']) == ref['dst'])

trgt = 'permit ip host 10.66.86.1 host 192.168.1.2'
file = 'input.txt'
fp = open(file, 'r')
arr = []
line = fp.readline()
while line:
    dct = convert_ace_data(line)
    arr.append(dct)
    line = fp.readline()

trgt = convert_ace_data(trgt)
for x in arr:
    if cmp_data(trgt, x):
        print(x['raw'])

fp.close()