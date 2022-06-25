# OpenVAS Vulnerability Test
# $Id: phpSurveyor_sql_inject.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: PHPSurveyor sid SQL Injection Flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2006 David Maciejak
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20376");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-4586");
  script_bugtraq_id(16077);
  script_name("PHPSurveyor sid SQL Injection Flaw");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2006 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to PHPSurveyor version 0.991 or later.");

  script_tag(name:"summary", value:"The remote version of PHPSurveyor is prone to a SQL injection flaw.");

  script_tag(name:"impact", value:"Using specially crafted requests, an attacker can manipulate database
  queries on the remote system.");

  script_xref(name:"URL", value:"http://www.phpsurveyor.org/mantis/view.php?id=286");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=381050&group_id=74605");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port) )
  exit(0);

foreach dir( make_list_unique( "/phpsurveyor", "/survey", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir,"/admin/admin.php?sid=0'");

  if(http_vuln_check(port:port, url:url,pattern:"mysql_num_rows(): supplied argument is not a valid MySQL .+/admin/html.php")) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );