###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortimail_xss_72820.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Fortinet FortiMail Web Action Quarantine Release Feature Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105239");
  script_bugtraq_id(72820);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-8617");

  script_name("Fortinet FortiMail Web Action Quarantine Release Feature Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72820");
  script_xref(name:"URL", value:"http://www.fortinet.com/products/fortimail/");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response");

  script_tag(name:"insight", value:"The application does not validate the parameter 'release' in
'/module/releasecontrol?release='");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"Fortinet FortiMail is prone to a cross-site scripting vulnerability
because it fails to properly sanitize user-supplied input.");

  script_tag(name:"affected", value:"FortiMail version 5.2.1");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-18 13:18:03 +0100 (Wed, 18 Mar 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");


port = get_http_port( default:443 );

url = '/module/releasecontrol?';

if( http_vuln_check( port:port, url:url, pattern:"<TITLE>Fortinet FortiMail</TITLE>" ) )
{
  url = '/module/releasecontrol?release=1:aaa:aaaaaaa<script>alert(/OpenVAS-XSS-Test/)</script>';
  if( http_vuln_check( port:port, url:url, pattern:"<script>alert\(/OpenVAS-XSS-Test/\)</script>", extra_check:"200 OK" ) )
  {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
