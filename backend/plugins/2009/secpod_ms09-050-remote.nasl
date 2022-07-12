###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-050-remote.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Microsoft Windows SMB2 Negotiation Protocol Remote Code Execution Vulnerability
#
# Authors:
# Chandrashekhar B <bchandra@secpod.com>
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900965");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-10-15 12:43:47 +0200 (Thu, 15 Oct 2009)");
  script_bugtraq_id(36299);
  script_cve_id("CVE-2009-2526", "CVE-2009-2532", "CVE-2009-3103");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows SMB2 Negotiation Protocol Remote Code Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Windows : Microsoft Bulletins");
  script_copyright("Copyright (C) 2009 SecPod");
  script_dependencies("os_detection.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Host/runs_windows");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS09-050.mspx");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute code with SYSTEM-level
  privileges. Failed exploit attempts will likely cause denial-of-service conditions.");

  script_tag(name:"affected", value:"- Windows 7 RC

  - Windows Vista and

  - Windows 2008 Server");

  script_tag(name:"insight", value:"Multiple vulnerabilities exists,

  - A denial of service vulnerability exists in the way that Microsoft Server
  Message Block (SMB) Protocol software handles specially crafted SMB version 2 (SMBv2) packets.

  - Unauthenticated remote code execution vulnerability exists in the way
  that Microsoft Server Message Block (SMB) Protocol software handles specially crafted SMB packets.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-050.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");

port = kb_smb_transport();
if( ! port ) port = 445;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

data = raw_string( 0x00,0x00,0x00,0x90,0xff,0x53,0x4d,0x42,0x72,0x00,0x00,0x00,0x00,0x18,0x53,0xc8,
                   0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xfe,
                   0x00,0x00,0x00,0x00,0x00,0x6d,0x00,0x02,0x50,0x43,0x20,0x4e,0x45,0x54,0x57,0x4f,
                   0x52,0x4b,0x20,0x50,0x52,0x4f,0x47,0x52,0x41,0x4d,0x20,0x31,0x2e,0x30,0x00,0x02,
                   0x4c,0x41,0x4e,0x4d,0x41,0x4e,0x31,0x2e,0x30,0x00,0x02,0x57,0x69,0x6e,0x64,0x6f,
                   0x77,0x73,0x20,0x66,0x6f,0x72,0x20,0x57,0x6f,0x72,0x6b,0x67,0x72,0x6f,0x75,0x70,
                   0x73,0x20,0x33,0x2e,0x31,0x61,0x00,0x02,0x4c,0x4d,0x31,0x2e,0x32,0x58,0x30,0x30,
                   0x32,0x00,0x02,0x4c,0x41,0x4e,0x4d,0x41,0x4e,0x32,0x2e,0x31,0x00,0x02,0x4e,0x54,
                   0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00,0x02,0x53,0x4d,0x42,0x20,0x32,0x2e,
                   0x30,0x30,0x32,0x00 );

send( socket:soc, data:data );
resp = smb_recv( socket:soc );
close( soc );
# '0xff' -> SMBv1 - Windows XP Profesional, Version 202, SP3
# '0xff' -> SMBv1 - Samba 3.0.33
# '0xfe' -> SMBv2 - Windows Server@enterprise (2008), SP
#  After applying patch, strlen(resp) is > 77

if( resp ) {

  if( strlen( resp ) < 9 ) exit( 0 );

  if( ord( resp[4]) == 255 && ord( resp[5] ) == 83 && ord( resp[6] ) == 77 && ord( resp[7] ) == 66 &&
      ord( resp[8] ) == 114 && strlen( resp ) == 77 ) {
    security_message( port:port );
    exit( 0 );
  }
  exit( 99 );
}

exit( 0 );