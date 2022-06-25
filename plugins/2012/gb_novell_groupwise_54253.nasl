###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_groupwise_54253.nasl 11169 2018-08-30 14:20:05Z asteins $
#
# Novell Groupwise WebAccess 'User.interface' Parameter Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103519");
  script_bugtraq_id(54253);
  script_cve_id("CVE-2012-0410");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 11169 $");
  script_name("Novell Groupwise WebAccess 'User.interface' Parameter Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54253");
  script_xref(name:"URL", value:"http://www.novell.com/groupwise/");
  script_tag(name:"last_modification", value:"$Date: 2018-08-30 16:20:05 +0200 (Thu, 30 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-07-16 12:02:03 +0200 (Mon, 16 Jul 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
information.");
  script_tag(name:"summary", value:"Groupwise is prone to a directory-traversal vulnerability because it
fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"Remote attackers can use specially crafted requests with directory-
traversal sequences ('../') to retrieve arbitrary files in the context
of the application.

Exploiting this issue may allow an attacker to obtain sensitive
information that could aid in further attacks.");

  script_tag(name:"affected", value:"Groupwise versions 8.0x through 8.02 HP3 are affected.");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/gw", "/servlet", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + '/webacc?User.interface=/../webacc/wml';

  if( http_vuln_check( port:port, url:url, pattern:"<wml>", extra_check:make_list( "<template>", "Novell GroupWise", "<onevent" ) ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
