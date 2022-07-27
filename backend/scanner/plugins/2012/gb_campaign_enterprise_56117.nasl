###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_campaign_enterprise_56117.nasl 11144 2018-08-28 11:37:19Z asteins $
#
# Campaign Enterprise Multiple Security Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.103586");
  script_bugtraq_id(56117);
  script_cve_id("CVE-2012-3820", "CVE-2012-3821", "CVE-2012-3822", "CVE-2012-3823", "CVE-2012-3824");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11144 $");
  script_name("Campaign Enterprise Multiple Security Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56117");
  script_xref(name:"URL", value:"http://www.arialsoftware.com/enterprise.htm");
  script_tag(name:"last_modification", value:"$Date: 2018-08-28 13:37:19 +0200 (Tue, 28 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-10-22 13:15:10 +0200 (Mon, 22 Oct 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"summary", value:"Campaign Enterprise is prone to multiple security vulnerabilities
including:

1. Multiple security-bypass vulnerabilities

2. Multiple information-disclosure vulnerabilities

3. Multiple SQL injection vulnerabilities");

  script_tag(name:"impact", value:"Attackers can exploit these issues to bypass certain security
restrictions, obtain sensitive information, and carry out
unauthorized actions on the underlying database. Other attacks may
also be possible.");

  script_tag(name:"affected", value:"Campaign Enterprise 11.0.538 is vulnerable.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_asp( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + '/User-Edit.asp?UID=1%20OR%201=1';

  if( http_vuln_check( port:port, url:url, pattern:"<title>Campaign Enterprise", extra_check:make_list( ">Logout</a>", "Edit User", "Admin Rights" ) ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
