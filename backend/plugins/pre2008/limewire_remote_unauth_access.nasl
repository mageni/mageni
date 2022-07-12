###############################################################################
# OpenVAS Vulnerability Test
# $Id: limewire_remote_unauth_access.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Lime Wire Multiple Remote Unauthorized Access
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

#  Ref: Kevin Walsh <kwalsh at cs.cornell.edu>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17973");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(12802);
  script_cve_id("CVE-2005-0788", "CVE-2005-0789");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Lime Wire Multiple Remote Unauthorized Access");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Peer-To-Peer File Sharing");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 6346);
  script_mandatory_keys("limewire/banner");

  script_tag(name:"solution", value:"Upgrade at least to version 4.8");
  script_tag(name:"summary", value:"The remote host seems to be running Lime Wire, a P2P file sharing program.

  This version is vulnerable to remote unauthorized access flaws.
  An attacker can access to potentially sensitive files on the
  remote vulnerable host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:6346 );
banner = get_http_banner( port:port );
if( ! banner ) exit( 0 );

serv = strstr(banner, "Server");
if( ! egrep( pattern:"limewire", string:serv, icase:TRUE ) ) exit( 0 );

files = traversal_files();
foreach file( keys( files ) ) {

  url = "/gnutella/res/";
  if( files[file] >< "ini" ) url = url + "C:\" + files[file];
  else url = url + "/" + files[file];

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );