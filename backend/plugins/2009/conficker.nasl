############################################################################
# OpenVAS Vulnerability Test
#
# Conficker Detection
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

#############################################################################
#  Based on the work of Tim Brown <timb@nth-dimension.org.uk> as published
#  here, http://www.nth-dimension.org.uk/blog.php?id=72 along with the
#  associated NASL from SecPod
#
#  Updated SRVSVC and ntrPathCanonicalize Request Packets with Description.
#   - By Chandan S
#############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900091");
  script_version("2019-05-03T08:55:39+0000");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-04-17 13:24:25 +0200 (Fri, 17 Apr 2009)");
  script_bugtraq_id(31874);
  script_cve_id("CVE-2008-4250");
  script_copyright("Copyright (C) 2009 SecPod");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_ATTACK);
  script_family("Malware");
  script_name("Conficker Detection");
  script_dependencies("nmap_nse/gb_nmap_p2p_conficker.nasl", "nmap_nse/gb_nmap_smb_check_vulns.nasl",
                      "os_detection.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("SMB/samba");

  script_xref(name:"URL", value:"http://www.dshield.org/diary.html?storyid=5860");
  script_xref(name:"URL", value:"http://www.anti-spyware-101.com/remove-conficker");
  script_xref(name:"URL", value:"http://iv.cs.uni-bonn.de/wg/cs/applications/containing-conficker/");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-067.mspx");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to take complete
  control of an affected system and capable of stealing all kind of sensitive information and can even
  spread across the Network.");

  script_tag(name:"affected", value:"Microsoft Windows 2K Service Pack 4 and prior.

  Microsoft Windows XP Service Pack 3 and prior.

  Microsoft Windows 2003 Service Pack 2 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.

  Additionally use a Conficker Removal Tool, or a known Security Product to remove the conficker worm.");

  script_tag(name:"summary", value:"This host seems to be contaminated with infectious Conficker Worm.");

  script_tag(name:"insight", value:"Conficker is a worm that spreads on Windows Platforms. This malware could
  spread Windows file shares protected with weak passwords or to which a logged on domain administrator has
  access, by copying itself to removable storage devices and by exploiting the MS08-067 Windows Server service
  vulnerability.

  This malware generates infections files to set up to run as a service and also using a random name when Windows
  starts under system32, and tries to modify permissions on the service registry entries so that they are not
  visible to the user. Such registry entries are under,

  'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost' and

  'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RANDOM_SERVICE_NAME'

  The plugin determines Conficker variants B or C. It likely works against systems that allow anonymous login,
  otherwise Credentials can be supplied.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-067.mspx");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");

if( kb_smb_is_samba() ) exit( 0 );

# First of all check whether nmap already detected an infection.
res = get_kb_list("conficker/nse");
if (!isnull(res)) {
  report = 'Nmap (http://nmap.org) has detected a possible infection:\n';

  foreach msg (res) {
    report += msg + '\n';
  }
  security_message(port:0, data:report);
  exit(0);
}

name = kb_smb_name();
login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();
port = kb_smb_transport();

soc = open_sock_tcp(port);
if(!soc){
 exit(0);
}

r = smb_session_request(soc:soc, remote:name);
if(!r) { close(soc); exit(0); }

if(!domain){
  domain = "";
}

if(!login && !pass)
{
  login = "";
  pass = "";
  prot = smb_neg_prot_anonymous(soc:soc);
}

else {
  prot = smb_neg_prot(soc:soc);
}

if(!prot)
{
  close(soc);
  exit(0);
}

##Validate length of response
if(strlen(prot) < 5 ) {
  exit(0);
}

##Currently Only SMB1 is supported, For SMB2 ord(prot[4]) == 254
if(ord(prot[4]) == 254)
{
  ##Close current Socket
  close(soc);
  ## Open a new Socket
  soc = open_sock_tcp(port);
  if(!soc){
   exit(0);
  }

  ##Session Request
  r = smb_session_request(soc:soc, remote:name);
  if(!r) { close(soc); exit(0); }

  prot = smb_neg_prot_NTLMv1(soc:soc);
  if(!prot)
  {
    close(soc);
    exit(0);
  }
}

r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
if(!r)
{
  close(soc);
  report = string("MS08-067: Failed to perform Clear Text based authentication.");
  exit(0);
}

uid = session_extract_uid(reply:r);
if(!uid)
{
  close(soc);
  exit(0);
}

r = smb_tconx(soc:soc, uid:uid, share:"IPC$", name:name);
if(!r)
{
  close(soc);
  exit(0);
}

tid = tconx_extract_tid(reply:r);
if(!tid)
{
  close(soc);
  exit(0);
}

tid_high = tid / 256;
tid_low  = tid % 256;
uid_high = uid / 256;
uid_low  = uid % 256;

# \srvsvc Request
req = raw_string(0xff, 0x53, 0x4d, 0x42, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x18,
                 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0xea, 0x16,
                 uid_low, uid_high, 0x00, 0x00, 0x18, 0xff, 0x00, 0x00, 0x00,
                 0x00, 0x08, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x9f, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
                 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x02,
                 0x00, 0x00, 0x00, 0x03, 0x09, 0x00, 0x5c, 0x62, 0x72, 0x6f,
                 0x77, 0x73, 0x65, 0x72, 0x00);

req = raw_string(0x00, 0x00, 0x00, (strlen(req)%256)) + req;
send(socket:soc, data:req);
resp = smb_recv(socket:soc);
if(strlen(resp) < 139)
{
  close(soc);
  exit(0);
}

fid_low = ord(resp[42]);
fid_high = ord(resp[43]);

# srvsvc Bind Request
req = raw_string(0xff, 0x53, 0x4d, 0x42, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0xea, 0x16,
                 uid_low, uid_high, 0x00, 0x00, 0x10, 0x00, 0x00, 0x48, 0x00,
                 0x00, 0x04, 0xe0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x48, 0x00,
                 0x4a, 0x00, 0x02, 0x00, 0x26, 0x00, fid_low, fid_high, 0x4f, 0x00,
                 0x5c, 0x50, 0x49, 0x50, 0x45, 0x5c, 0x00, 0x05, 0x00, 0x0b,
                 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01,
                 0x00, 0x00, 0x00, 0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00,
                 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc8,
                 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a,
                 0x47, 0xbf, 0x6e, 0xe1, 0x88, 0x03, 0x00, 0x00, 0x00, 0x04,
                 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08,
                 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00);

req = raw_string(0x00, 0x00, 0x00, (strlen(req)%256)) + req;
send(socket:soc, data:req);
smb_recv(socket:soc);

# ntrPathCanonicalize Request (With Malicious Code)
req = raw_string(
0xff, 0x53, 0x4d, 0x42, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
tid_low, tid_high,
0xea, 0x16,
uid_low, uid_high,
0x00, 0x00, 0x10, 0x00, 0x00, 0x60, 0x00, 0x00, 0x04, 0xe0, 0xff, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x60,
0x00, 0x4a, 0x00, 0x02, 0x00, 0x26, 0x00, fid_low, fid_high, 0x67, 0x00, 0x5c, 0x50,
0x49, 0x50, 0x45, 0x5c, 0x00, 0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00,
0x00, 0x1f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x5c, 0x00, 0x2e, 0x00,
0x2e, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x5c, 0x00,
0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00);

req = raw_string(0x00, 0x00, 0x00, 0xaa) + req;

send(socket:soc, data:req);
resp = smb_recv(socket:soc);
close(soc);

if(strlen(resp) < 100){
  exit(0);
}

if(ord(resp[96]) == 87 && ord(resp[97]) == 00 && ord(resp[98]) == 00 && ord(resp[99]) == 00)
{
  security_message(port:0);
  exit(0);
}

exit(99);
