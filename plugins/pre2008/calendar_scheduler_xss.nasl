###############################################################################
# OpenVAS Vulnerability Test
# $Id: calendar_scheduler_xss.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Topic Calendar XSS
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# "Alberto Trivero" <trivero@jumpy.it>
# Multiple vulnerabilities in Topic Calendar 1.0.1 for phpBB
# 2005-03-24 02:14

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17613");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2005-0872");
  script_bugtraq_id(12893);
  script_name("Topic Calendar XSS");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "cross_site_scripting.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Disable this module or upgrade to a newer version");
  script_tag(name:"summary", value:"The remote web server is running Topic Calendar, a module for phpBB which adds
  calendaring support to phpBB. This script is vulnerable to a cross site scripting issue.");
  script_tag(name:"impact", value:"Due to improper filtering done by the script 'calendar_scheduler.php' a
  remote attacker can cause the Topic Calendar product to include arbitrary HTML and/or JavaScript.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + '/calendar_scheduler.php?start="><script>alert(document.cookie)</script>';

  if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:'start="><script>alert(document.cookie)</script>" class=' ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
