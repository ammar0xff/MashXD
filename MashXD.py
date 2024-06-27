import argparse
import hashlib
import zipfile
import pyfiglet.fonts
import rarfile
import os
from pathlib import Path
from termcolor import colored
import binascii
import pyfiglet 
import argparse

#---------------------------------------------------------------------Header----------------------------------------------------------------------------
print(colored(pyfiglet.figlet_format("MashXD"),"magenta") + colored( "## Made By ammar0xff ##\n","light_green"))

#-------------------------------------------------------------------- args handling---------------------------------------------------------------------
parser = argparse.ArgumentParser(
                            prog='MashXD',
                            epilog='MashXD is a Malware Detector (based on hash list comparing)',
                            conflict_handler="error",
                            usage="MashXD.py -l <list.txt> -f <file.zip>"
                            )

# parser.add_argument("--no-unpacking",required=False,metavar="",dest="mode",help="to scan all the files in the current directory without unpacking any archive." )   # soon..
parser.add_argument("-l",metavar="",action="store",dest="hash_list",required=True,help="the hashes list filename." )
parser.add_argument("-f",required=True,metavar="",dest="first_archive",help="the malware zip archive to scan." )

args = parser.parse_args()
hash_list = args.hash_list
first_archive = args.first_archive

#--------------------------------------------------------------------Lists & Archives---------------------------------------------------------------------
BigArchiveDict = {}
target_files = []
unwanted = '\n'
print("")


#--------------------------------------------------------------------Algorithms----------------------------------------------------------------------------
Hash_Algorithms = ['sha256', 'md5', 'blake2s', 'blake2b', 'sha1', 'sha224', 'sha512', 'sha3_256', 'sha3_512', 'sha384', 'blake2b', 'sha3_224', 'sha3_384']
Checksum_Algorithms = ['crc32']

#--------------------------------------------------------------------Hash List Handling--------------------------------------------------------------------
Mal_Hashes_FILE = open(hash_list,"r")
Mal_Hashes = Mal_Hashes_FILE.readlines()

for index,MalHashes in enumerate(Mal_Hashes):
    Mal_Hashes[index] = MalHashes.replace(unwanted, '')


#--------------------------------------------------------------------Unpacking first Archive---------------------------------------------------------------
zip_ref = zipfile.ZipFile(first_archive, 'r')
for member in zip_ref.namelist():
        print(colored("[*] ","light_blue") + colored("extracting ","light_green") + member + colored(" from ","magenta") + first_archive)
        zip_ref.extractall()

#--------------------------------------------------------------------changing dir for upcoming operations--------------------------------------------------
os.chdir((next(os.walk("."))[1][0]))


for ZipArchiveFile in os.listdir() :
    ZipArchivesList = []
    
#--------------------------------------------------------------------creating a list for ,zip files---------------------------------------------------------
    if ZipArchiveFile.endswith(".zip"):
        ZipArchivesList.append(ZipArchiveFile)
        
        for file in ZipArchivesList:
                zip_ref = zipfile.ZipFile(file, 'r')
                
                for member in zip_ref.namelist():
                    
#--------------------------------------------------------------------creating a list for the members of all .zip files---------------------------------------
                    ZipMembers = []
                    ZipMembers.append(member)

#--------------------------------------------------------------------printing out the details of the unpacking operation-------------------------------------
                    print(colored("[*] ","light_blue") + colored("extracting ","light_green") + member + colored(" from ","magenta") + file)
                    
#--------------------------------------------------------------------extracting all the files from all .zip files--------------------------------------------
                zip_ref.extractall()
                
#--------------------------------------------------------------------creating a dict contains the extracted files as a keys and the .zip files as a value----
                ZipDict = {str(zip_ref.namelist()):file}
                
#--------------------------------------------------------------------putting every element of the Zip Dict inside a global one for both .rar and .zip archives
                for v in ZipDict:
                    BigArchiveDict.update(ZipDict)

for RarArchiveFile in os.listdir() :
    RarArchivesList = []
    
#--------------------------------------------------------------------creating a list for .rar files------------------------------------------------------------
    if RarArchiveFile.endswith(".rar"):
        RarArchivesList.append(RarArchiveFile)
        
        for file in RarArchivesList:
                rar_ref = rarfile.RarFile(file, 'r')
                
                for member in rar_ref.namelist():
                    
#--------------------------------------------------------------------creating a list for the members of all .rar files------------------------------------------
                    RarMembers = []
                    RarMembers.append(member)
                    
#--------------------------------------------------------------------printing out the details of the unpacking operation----------------------------------------
                    print(colored("[*] ","light_blue") + colored("extracting ","light_green") + member + colored(" from ","magenta") + file)
                    
#--------------------------------------------------------------------extracting all the files from all .rar files-----------------------------------------------
                rar_ref.extractall()
                
#--------------------------------------------------------------------creating a dict contains the extracted files as a keys and the .rar files as a value-------
                RarDict = {str(rar_ref.namelist()):file}
                
#--------------------------------------------------------------------putting every element of the Zip Dict inside a global one for both .rar and .zip archives--
                for v in RarDict:
                    BigArchiveDict.update(RarDict)
print("")

#--------------------------------------------------------------------creating a list containing all files except the archives with name "target_Files"----------
for i in os.listdir():
    if (i.endswith(".zip") == False) and ((i.endswith(".rar")) == False)   :
        target_files.append(i)
        

print(colored("Malwares Detected:","cyan"))

for file in target_files:
    
#--------------------------------------------------------------------defining the CRC32 checksum algorithm-------------------------------------------------------
    def CRC32_from_file(filename):
        buf = open(filename,'rb').read()
        buf = (binascii.crc32(buf) & 0xFFFFFFFF)
        return "%08X" % buf
        
#--------------------------------------------------------------------Defining the var of the CRC32 of all files and comparing it to the mal hashes list-----------
    crc32 = CRC32_from_file(file).lower()
    if  crc32 in Mal_Hashes :
        
#--------------------------------------------------------------------getting the archive of the mal file with the size and full path------------------------------
        exec( 'Mal_Archive = BigArchiveDict.get("' + '[' + "'" + file + "'" + "]" + '"' + ")")
        FileSize = os.stat(file).st_size
        FileDir = os.path.abspath(file)
        
#--------------------------------------------------------------------printing out the full report of every checksum mal-------------------------------------------
        print(colored("\n" + file + " :\n      ","light_red" )+ colored("Archive File: ","blue" )+ str(Mal_Archive) + " \n"  + colored("      File Size: ","blue" )+ str(FileSize) + " Bytes" + colored( "\n      Malware Checksum: ","blue") + "\n          Algorithm: " + "crc32" + "\n          Value: " + crc32 + colored(  "\n      Full Path: ","blue") + FileDir + "   "  )# type: ignore

#--------------------------------------------------------------------doing the same stuff of every hashes mals----------------------------------------------------
    else:
        for hash_algorithm in Hash_Algorithms:
            
#--------------------------------------------------------------------reading the files as bytes to calc the hash of them------------------------------------------
                with open(file, "rb") as FILE:
                    data = FILE.read()
                    
#--------------------------------------------------------------------defining the pure hash value of each file----------------------------------------------------
                    exec("hash_value = " + "hashlib." + str(hash_algorithm) + "(data).hexdigest() " )
                    
#--------------------------------------------------------------------checking out for any matches in the mal hashes-----------------------------------------------
                    if ((hash_value in Mal_Hashes) == True) :
                        
#--------------------------------------------------------------------getting the archive of the mal file with the size and full path------------------------------
                            exec( 'Mal_Archive = BigArchiveDict.get("' + '[' + "'" + file + "'" + "]" + '"' + ")")
                            FileSize = os.stat(file).st_size
                            FileDir = os.path.abspath(file)
                            
#--------------------------------------------------------------------printing out the full report of every hash mal------------------------------------------------
                            print(colored("\n" + file + " :\n      ","light_red" )+ colored("Archive File: ","blue" )+ str(Mal_Archive) + " \n"  + colored("      File Size: ","blue" )+ str(FileSize) + " Bytes" + colored( "\n      Malware Hash: ","blue") + "\n          Algorithm: " + hash_algorithm + "\n          Value: " + hash_value +colored(  "\n      Full Path: ","blue") + FileDir + "   "  )# type: ignore
                            
                FILE.close()

