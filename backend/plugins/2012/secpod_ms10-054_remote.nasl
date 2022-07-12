###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SMB Server Trans2 Request Remote Code Execution Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902662");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2010-2550", "CVE-2010-2551", "CVE-2010-2552");
  script_bugtraq_id(42224, 42263, 42267);
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-02-29 12:16:56 +0530 (Wed, 29 Feb 2012)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft SMB Server Trans2 Request Remote Code Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_smb_accessible_shares.nasl", "os_detection.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
  script_mandatory_keys("SMB/Accessible_Shares", "Host/runs_windows");
  script_require_ports(139, 445);
  script_exclude_keys("SMB/samba");

  script_xref(name:"URL", value:"http://secunia.com/advisories/40935/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/47674");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14607/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-002/");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS10-054");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code on the system and cause a denial of service condition.");

  script_tag(name:"affected", value:"Microsoft Windows 7

  Microsoft Windows 2008 SP2 and prior

  Microsoft Windows Vista SP2 and prior

  Microsoft Windows XP Service Pack 3 and prior

  Microsoft Windows 2003 Service Pack 2 and prior");

  script_tag(name:"insight", value:"The flaw is due to improper validation of SMB Trans2 request by SMB
  server, which allows remote attackers to execute arbitrary code on the
  system by sending a malformed SMB Trans2 request.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-054.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");

if( kb_smb_is_samba() ) exit( 0 );

name   = kb_smb_name();
domain = kb_smb_domain();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

if(!login)login = "anonymous";
if(!pass) pass = "";

shares = get_kb_list("SMB/Accessible_Shares");
if (isnull(shares))
{
  close(soc);
  exit(0);
}

prot = smb_neg_prot(soc:soc);
if(!prot){
  close(soc);
  exit(0);
}

if(strlen(prot) < 5 ) {
  exit(0);
}

##Currently Only SMB1 is supported, For SMB2 ord(prot[4]) == 254
if(ord(prot[4]) == 254)
{
  close(soc);
  soc = open_sock_tcp(port);
  if(!soc){
   exit(0);
  }

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
  exit(0);
}

uid = session_extract_uid(reply:r);
if(!uid)
{
  close(soc);
  exit(0);
}

foreach share (shares)
{
  r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
  if(!r){
    continue;
  }

  tid = tconx_extract_tid(reply:r);
  if(!tid){
    continue;
  }

  tid_high = tid / 256;
  tid_low  = tid % 256;
  uid_high = uid / 256;
  uid_low  = uid % 256;

  req = raw_string(0x00, 0x00, 0x00, 0x44,
                   0xff, 0x53, 0x4d, 0x42,             # Server Component
                   0x32,                               # SMB Command , x32 for Trans2
                   0x00, 0x00, 0x00, 0x00,             # NT_Status : Success
                   0x18, 0x03, 0xc8, 0x00, 0x00,       # Flags
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00,             # Signature & Reserved
                   tid_low, tid_high, 0x00, 0x28,
                   uid_low, uid_high, 0x00, 0x01,
                   0x0f,                               # Word Count
                   0x02, 0x00,                         # Total Parameter Count
                   0x00, 0x00,                         # Total Data Count
                   0x00, 0x00,                         # Max Parameter Count
                   0x0f, 0x00,                         # Max Data Count
                   0x00, 0x00, 0x00, 0x00,             # Max setup Count & Reserved & e bytes for Flags
                   0x00, 0x00, 0x00, 0x00,             # TimeOut
                   0x00, 0x00,                         # Reserved
                   0x02, 0x00,                         # Parameter Count
                   0x42, 0x00,                         # Parameter Offset
                   0x00, 0x00, 0x44, 0x00,             # Data Count & Data Offset
                   0x01, 0x00,                         # Setup Count & Reserved
                   0x03, 0x00,                         # Subcommand : QUERY_FS_INFO
                   0x03, 0x00,                         # Byte Count
                   0x00,                               # Padding
                   0x05, 0x01);                        # QUERY_FS_INFO Parameters

  send(socket:soc, data:req);
  resp = smb_recv(socket:soc);

  if( strlen( resp ) < 13 ) continue;

  ## nb: Check if SMB NT_STATUS is STATUS_BUFFER_OVERFLOW (0x80000005)
  if(resp && ord(resp[9]) == 5 && ord(resp[10]) == 0 &&
             ord(resp[11]) == 0 && ord(resp[12]) == 128)
  {
    security_message(port);
    close(soc);
    exit(0);
  }
}

close( soc );
exit( 99 );
