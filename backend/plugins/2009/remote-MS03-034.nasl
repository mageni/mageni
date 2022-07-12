###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-MS03-034.nasl 14325 2019-03-19 13:35:02Z asteins $
#
# Microsoft Security Bulletin MS03-034 Flaw in NetBIOS Could Lead to Information Disclosure
#
# Affected software
#
# Microsoft Windows NT Workstation 4.0
# Microsoft Windows NT Server 4.0®
# Microsoft Windows NT Server 4.0, Terminal Server Edition
# Microsoft Windows 2000
# Microsoft Windows XP
# Microsoft Windows Server 2003
#
# Not Affected Software:
#
# Microsoft Windows Millennium Edition
#
# remote-MS03-034.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later,
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
  script_oid("1.3.6.1.4.1.25623.1.0.101015");
  script_version("$Revision: 14325 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:35:02 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-03-16 23:15:41 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2003-0661");
  script_name("Microsoft MS03-034 security check");
  script_category(ACT_ATTACK);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("find_service.nasl", "os_detection.nasl");
  script_require_udp_ports(137);
  script_mandatory_keys("Host/runs_windows");

  script_tag(name:"solution", value:"Microsoft has released patches to fix this issue.
  Please see the references for more information.");

  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=A59CC2AC-F182-4CD5-ACE7-3D4C2E3F1326&displaylang=en");
  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=140CF7BE-0371-4D17-8F4C-951B76AC3024&displaylang=en");
  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=1C9D8E86-5B8C-401A-88B2-4443FFB9EDC3&displaylang=en");
  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=378D4B58-BF2C-4406-9D88-E6A3C4601795&displaylang=en");
  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=D0564162-4EAE-42C8-B26C-E4D4D496EAD8&displaylang=en");
  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=F131D63A-F74F-4CAF-95BD-D7FA37ADCF38&displaylang=en");
  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=22379951-64A9-446B-AC8F-3F2F080383A9&displaylang=en");

  script_tag(name:"summary", value:"Under certain conditions, the response to a NetBT Name Service query may, in addition to the typical reply,
  contain random data from the target system's memory. This data could, for example, be a segment of HTML
  if the user on the target system was using an Internet browser, or it could contain other types of data
  that exist in memory at the time that the target system responds to the NetBT Name Service query.
  An attacker could seek to exploit this vulnerability by sending a NetBT Name Service query to the target system
  and then examine the response to see if it included any random data from that system's memory.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");

port = 137;
if( ! get_udp_port_state( port ) ) exit( 0 );

matrix = make_array();

request = raw_string("\x7c\x54\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00",
                     "\x20\x43\x4B\x41\x41\x41\x41\x41\x41\x41\x41\x41",
                     "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41",
                     "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21",
                     "\x00\x01");

for( i = 0; i < 50; i++ ) {

  soc = open_sock_udp( port );
  if( ! soc ) exit( 0 );

  send( socket:soc, data:request );

  response = recv( socket:soc, length:4096, timeout:20 );
  close( soc );

  if( strlen( response ) > 58 ) {
    min = strlen( response ) - 58;
    element = substr( response, min, strlen( response ) );
    matrix[max_index(matrix)] = element;
  }

  # the length of the aray
  dim = max_index( matrix ) - 1;
  if( dim > 1 ) {
    for( j = 0; j < i; j++ ) {
      if( matrix[j] != matrix[i] ) {
      # Report Microsoft Windows 'NetBT Name Service' Information Leakage Vulnerability (MS03-034)
        security_message( port:port, proto:"udp" );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
