from globalValue import GLOBAL_VAR
from distorm3 import Decode, Decode64Bits

queue = []
queue_size = 3
data = []
apicall = []

def save(data, filename):
    f = open(filename, 'w')
    for i in data:
        f.write(str(i)+'\n')
    f.close()


def unwrap(dumps, OEP:int):
    l = Decode(0x0000, open("5368713984", "rb").read()[0x1000:], Decode64Bits)
    for i in l:
        #print("0x%08x (%02x) %-20s %s" % (i[0],  i[1],  i[3],  i[2]))
        
        if "CALL" in i[2]: 
            if int(i[3],16) >> 32 == 0xe8:
                data.append([i[0],  i[1],  i[3],  i[2]])
            elif int(i[3],16) >> 32 == 0xff15:
                data.append([i[0],  i[1],  i[3],  i[2]])
        
        
        # queue.insert(0,i)
        #if 'OR' in i[2].split(' '):
            #print("0x%08x (%02x) %-20s %s" % (i[0],  i[1],  i[3],  i[2]))
            #input()
        # if len(queue) == 3:
        #     if 'JMP' in queue[0][2] and 'OR' in queue[1][2] and 'JMP' in queue[0][3]:
        #         apicall.append(queue)
        # elif len(queue) > 3:
        #     queue.pop()

    save(apicall, "apicall.txt")
    save(data, "call.txt")
    

f = open("dump",'rb')#afterOEP755732
dump = f.read()
f.close()
unwrap(dump,755732)

