#from globalValue import GLOBAL_VAR
from distorm3 import Decode, Decode64Bits

queue = []
data = []
apicall = []

def save(data, filename):
    f = open(filename, 'w')
    for i in data:
        f.write(str(i)+'\n')
    f.close()


def unwrap(dumps, OEP:int):
    l = Decode(0x140000000, open("0x140001300", "rb").read()[0x1000:], Decode64Bits)
    # f= open('disasm.txt','w')
    for i in l:
        print("0x%08x (%02x) %-20s %s" % (i[0],  i[1],  i[3],  i[2]))

    #     f.write("0x%08x (%02x) %-20s %s\n" % (i[0],  i[1],  i[3],  i[2]))
    #     if "CALL" in i[2]: 
    #         if int(i[3],16) >> 32 == 0xe8:
    #             data.append([i[0],  i[1],  i[3],  i[2]])
    #         elif int(i[3],16) >> 32 == 0xff15:
    #             data.append([i[0],  i[1],  i[3],  i[2]])
    # f.close()

        
   
    # save(apicall, "apicall.txt")
    # save(data, "call.txt")
    

f = open("dump",'rb')#afterOEP755732
dump = f.read()
f.close()
unwrap(dump,755732)

