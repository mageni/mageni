###############################################################################
# OpenVAS Vulnerability Test
#
# Vulnerabilities in SMB Could Allow Remote Code Execution (958687) - Remote
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900233");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(31179);
  script_cve_id("CVE-2008-4114", "CVE-2008-4834", "CVE-2008-4835");
  script_name("Vulnerabilities in SMB Could Allow Remote Code Execution (958687) - Remote");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("os_detection.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Host/runs_windows");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6463");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms09-001.mspx");

  script_tag(name:"impact", value:"Successful exploitation could allow remote unauthenticated attackers
  to cause denying the service by sending a specially crafted network message
  to a system running the server service.");
  script_tag(name:"affected", value:"Microsoft Windows 2K Service Pack 4 and prior.

  Microsoft Windows XP Service Pack 3 and prior.

  Microsoft Windows 2003 Service Pack 2 and prior.");
  script_tag(name:"insight", value:"The issue is due to the way Server Message Block (SMB) Protocol software
  handles specially crafted SMB packets.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-001.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("smb_nt.inc");

name = kb_smb_name();
domain = kb_smb_domain();
port = kb_smb_transport();

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

login = "";
pass = "";

r = smb_session_request(soc:soc, remote:name);
if(!r) { close(soc); exit(0); }

prot = smb_neg_prot_cleartext(soc:soc);
if(!prot){ close(soc); exit(0); }

r = smb_session_setup_cleartext(soc:soc, login:login, password:pass, domain:domain);
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

r = smb_tconx_cleartext(soc:soc, uid:uid, share:"IPC$", name:name);
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

req = raw_string(0xff, 0x53, 0x4d, 0x42, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x08,
                 0x01, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0xa2, 0x4d,
                 uid_low, uid_high, 0x0b, 0x00, 0x18, 0xff, 0x00, 0x00,
                 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x9f, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
                 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x02, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x5c, 0x00,
                 0x62, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x77, 0x00, 0x73, 0x00,
                 0x65, 0x00, 0x72, 0x00, 0x00, 0x00 );

req = raw_string(0x00, 0x00, 0x00, (strlen(req)%256)) + req;
send(socket:soc, data:req);
resp = smb_recv(socket:soc);
if(strlen(resp) < 107)
{
  close(soc);
  exit(0);
}

fid_low = ord(resp[42]);
fid_high = ord(resp[43]);

req = raw_string(0xff, 0x53, 0x4d, 0x42, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x18,
                 0x03, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0xdc, 0x54,
                 uid_low, uid_high, 0x40, 0x01,
                 0x0e, 0xff, 0x00, 0x00, 0x00, fid_low,
                 fid_high, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
                 0xff, 0x08, 0x00, 0x48, 0x00, 0x00, 0x00, 0x48,
                 0x00, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49,
                 0x00, 0x00, 0x05, 0x00, 0x0b, 0x03, 0x10, 0x00,
                 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00,
                 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x01, 0x00, 0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16,
                 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e,
                 0xe1, 0x88, 0x03, 0x00, 0x00, 0x00, 0x04, 0x5d,
                 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8,
                 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
                 0x00, 0x00 );

req = raw_string(0x00, 0x00, 0x00, (strlen(req)%256)) + req;
send(socket:soc, data:req);
resp = smb_recv(socket:soc);
close(soc);

if(resp && ord(resp[8]) == 47 && ord(resp[9]) == 0 && ord(resp[10]) == 0
        && ord(resp[11]) == 0 && ord(resp[12]) == 0){
  security_message(port);
}
