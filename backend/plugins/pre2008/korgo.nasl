###############################################################################
# OpenVAS Vulnerability Test
#
# Korgo worm detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.12252");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Korgo worm detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Malware");
  script_dependencies("find_service.nasl", "os_detection.nasl");
  script_require_ports(445, 113, 3067);
  script_mandatory_keys("Host/runs_windows");

  script_xref(name:"URL", value:"http://securityresponse.symantec.com/avcenter/venc/data/w32.korgo.c.html");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS04-011.mspx");

  script_tag(name:"solution", value:"- Disable access to port 445 by using a firewall

  - Apply Microsoft MS04-011 patch.");

  script_tag(name:"summary", value:"The remote host is probably infected with Korgo worm.

  It propagates by exploiting the LSASS vulnerability on TCP port 445
  (as described in Microsoft Security Bulletin MS04-011)
  and opens a backdoor on TCP ports 113 and 3067.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

ports[0] = 3067;
ports[1] = 113;

if( get_port_state( ports[0] ) ) {

  soc1 = open_sock_tcp( ports[0] );
  if( soc1 ) {
    if( get_port_state( ports[1] ) ) {
      soc2 = open_sock_tcp( ports[1] );
      if( soc1 && soc2 ) {
        close( soc1 );
        close( soc2 );
        security_message( port:ports[0] );
      }
    }
  }
}

exit( 0 );