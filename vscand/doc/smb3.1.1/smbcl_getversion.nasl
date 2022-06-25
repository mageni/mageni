#
# This script was written by Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
#
# This script is released under the GNU GPLv2
#
# $Revision: 01 $

if(description)
{

 script_id(90011);
 script_version ("$Revision: 01 $");
 name["english"] = "SMB Test";
 script_name(english:name["english"]);

 desc["english"] = "Test remote host SMB Functions";

 script_description(english:desc["english"]);
 summary["english"] = "Determines the OS and SMB Version of Host";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is under GPLv2");
 family["english"] = "Windows SMB";
 script_family(english:family["english"]);
 exit(0);
}

#
# The code starts here
#

include("smbcl_func.inc");
if( !get_kb_item("SMB/smbclient") ) {
   smbclientavail();
}

  if(get_kb_item("SMB/smbclient") ) {
    if( smbversion() == 1){
      report = string("OS Version = "+get_kb_item("SMB/OS")) + string("\n");
      report = report + string("Domain = "+ get_kb_item("SMB/DOMAIN")) + string("\n");
      report = report + string("SMB Serverversion = "+ get_kb_item("SMB/SERVER")) + string("\n");
      security_note(port:0, proto:"SMBClient", data:report);
    } else {
      report = string("Error getting SMB-Data -> "+get_kb_item("SMB/ERROR"));
      security_note(port:0, proto:"SMBClient", data:report);
    }
  } else { 
    report = string("SMBClient not found on this host !");
    security_note(port:0, proto:"SMBClient", data:report);
    exit(0);
  }

exit(0);



#=====
#This is for testing only !
#Here you can see what is possible with smbcl_func.nasl
#This example will read the Versionnumber of all exe in the Windows\ Directory
#=====

  win_dir = get_windir();
#  path = win_dir+"Microsoft.NET\Framework\v2.0.50727\";
  path = win_dir; # +"SYSTEM32\";
  filespec = "*.exe";
#  filespec = "system.WEB.dll";

  r = smbgetdir(share: "C$", dir: path+filespec, typ: 1 );
  if( !isnull(r) ) {
    foreach i (keys(r)) {
      tmp_filename = get_tmp_dir()+"tmpfile"+rand();
      orig_filename = path+r[i];
      if( smbgetfile(share: "C$", filename: orig_filename, tmp_filename: tmp_filename) ) {
        report = string("SMB File successfully loaded ") + string("\n");
        v = GetPEFileVersion(tmp_filename:tmp_filename, orig_filename:orig_filename);
        unlink(tmp_filename);
        report = report + "Fileversion : C$ "+orig_filename + " "+v+string("\n");
        report = report + "KB Fileversion "+string("Getting SMB-KB File -> ")+get_kb_item("SMB/FILEVERSION/"+orig_filename) + string("\n");
        security_note(port:0, proto:"SMBClient", data:report);    
      } else {
        report = string("Error getting SMB-File -> "+get_kb_item("SMB/ERROR")) + string("\n");
        security_note(port:0, proto:"SMBClient", data:report);
      }
    }
  } else {
    report = string("No Files found according filespec : ")+path+filespec + string("\n");
    security_note(port:0, proto:"SMBClient", data:report);
  }
exit(0);
