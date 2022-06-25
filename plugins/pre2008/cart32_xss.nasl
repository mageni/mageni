###############################################################################
# OpenVAS Vulnerability Test
# $Id: cart32_xss.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Cart32 GetLatestBuilds XSS
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

# From: "Dr Ponidi" <drponidi@hackermail.com>
# Subject: Cart32 Input Validation Flaw in 'GetLatestBuilds?cart32=' Permits Remote Cross-Site Scripting Attacks
# Date: 27.6.2004 21:37

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12290");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0675");
  script_bugtraq_id(10617);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Cart32 GetLatestBuilds XSS");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"An attacker may use this bug to steal the credentials of the legitimate users
  of this site.");

  script_tag(name:"solution", value:"Upgrade to the newest version of this software");

  script_tag(name:"summary", value:"The remote host is using Cart32, a shopping cart software.

  There is a bug in this software which makes it vulnerable to cross site
  scripting attacks.");

  script_tag(name:"qod", value:"50"); # No extra check, prone to false positives and doesn't match existing qod_types
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
  url = dir + "/cart32.exe/GetLatestBuilds?cart32=%3Cscript%3Efoo%3C/script%3E";

  if( http_vuln_check( port:port, url:url, pattern:"<script>foo</script>", check_header:TRUE ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );