###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-012-remote.nasl 11684 2010-10-15 16:45:43Z oct$
#
# Microsoft Windows SMB Server NTLM  Multiple Vulnerabilities (971468)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
# Chandrashekhar B <bchandra@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902269");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-10-22 15:51:55 +0200 (Fri, 22 Oct 2010)");
  script_cve_id("CVE-2010-0020", "CVE-2010-0021", "CVE-2010-0022", "CVE-2010-0231");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows SMB Server NTLM Multiple Vulnerabilities (971468)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("netbios_name_get.nasl", "smb_nativelanman.nasl", "os_detection.nasl");
  script_require_ports(445);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("SMB/samba");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38510/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/971468");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0345");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms10-012.mspx");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code or cause a denial of service or bypass the authentication mechanism via brute force technique.");

  script_tag(name:"affected", value:"Microsoft Windows 7

  Microsoft Windows 2000 Service Pack and prior

  Microsoft Windows XP Service Pack 3 and prior

  Microsoft Windows Vista Service Pack 2 and prior

  Microsoft Windows Server 2003 Service Pack 2 and prior

  Microsoft Windows Server 2008 Service Pack 2 and prior");

  script_tag(name:"insight", value:"- An input validation error exists while processing SMB requests and can
  be exploited to cause a buffer overflow via a specially crafted SMB packet.

  - An error exists in the SMB implementation while parsing SMB packets during
  the Negotiate phase causing memory corruption via a specially crafted SMB packet.

  - NULL pointer dereference error exists in SMB while verifying the 'share'
  and 'servername' fields in SMB packets causing denial of service.

  - A lack of cryptographic entropy when the SMB server generates challenges
  during SMB NTLM authentication and can be exploited to bypass the authentication mechanism.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-012.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  script_timeout(360);

  exit(0);
}

include("smb_nt.inc");

if(kb_smb_is_samba())
  exit(0);

port = "445";
if(!get_port_state(port)){
  exit(0);
}

i = 0;
complet_key = "";

while(i < 5000) {

  soc = open_sock_tcp(port);
  if(!soc) {
    exit(0);
  }

  data = raw_string(0x00, 0x00, 0x00, 0x54, 0xff, 0x53, 0x4d, 0x42,
                    0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0xc0,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0x61,
                    0x00, 0x00, 0x54, 0x80, 0x00, 0x31, 0x00, 0x02,
                    0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e,
                    0x30, 0x00, 0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32,
                    0x58, 0x30, 0x30, 0x32, 0x00, 0x02, 0x4e, 0x54,
                    0x20, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x20,
                    0x31, 0x2e, 0x30, 0x00, 0x02, 0x4e, 0x54, 0x20,
                    0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00);
  send(socket: soc, data: data);
  resp = smb_recv(socket:soc);
  close(soc);
  if(resp && strlen(resp) > 80) {

    response = raw_string(substr(resp, 73, 73 + 7));

    if(response) {

      key_found = hexstr(response);

      # match the duplicate key
      if(key_found >< complet_key) {
        security_message(port:port);
        exit(0);
      }
    }

    ## If key does not match, add key to the list
    complet_key += " " + key_found;
  }
  i++;
}

exit(99);