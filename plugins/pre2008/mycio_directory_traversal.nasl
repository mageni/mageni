###############################################################################
# OpenVAS Vulnerability Test
# $Id: mycio_directory_traversal.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# McAfee myCIO Directory Traversal
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10706");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3020);
  script_cve_id("CVE-2001-1144");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("McAfee myCIO Directory Traversal");
  script_category(ACT_ATTACK);
  script_family("Remote file access");
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_dependencies("mycio_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 6515);
  script_mandatory_keys("mycio/installed");

  script_tag(name:"solution", value:"Configure your firewall to block access to this port (TCP 6515).
  Use the Auto Update feature of McAfee's myCIO to get the latest version.");

  script_tag(name:"summary", value:"The remote host runs McAfee's myCIO HTTP Server, which is vulnerable to Directory Traversal.");
  script_tag(name:"impact", value:"A security vulnerability in the product allows attackers to traverse outside the normal HTTP root
  path, and this exposes access to sensitive files.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:6515 );
if( ! get_kb_item( "mycio/" + port + "/installed" ) ) exit( 0 );

files = traversal_files( "windows" );
foreach file( keys( files ) ) {

  url = ".../.../.../.../" + files[file];

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );