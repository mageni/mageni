###############################################################################
# OpenVAS Vulnerability Test
# $Id: articlelive_xss.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Interspire ArticleLive 2005 XSS Vulnerability
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

# Interspire ArticleLive 2005 (php version) XSS vulnerability
# mircia <mircia@security.talte.net>
# 2005-03-24 14:54

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17612");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2005-0881");
  script_bugtraq_id(12879);
  script_name("Interspire ArticleLive 2005 XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "cross_site_scripting.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the newest version of this software");
  script_tag(name:"summary", value:"The remote web server is running ArticleLive, a set of CGIs designed to simplify
  the management of a news site which is vulnerable to a cross site scripting issue.");
  script_tag(name:"impact", value:"Due to improper filtering done by the script 'newcomment' remote attacker
  can cause the ArticleLive product to include arbitrary HTML and/or JavaScript, and therefore use the
  remote host to perform cross-site scripting attacks.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + '/newcomment/?ArticleId="><script>foo</script>';

  if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:'value=""><script>foo</script>"' ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
