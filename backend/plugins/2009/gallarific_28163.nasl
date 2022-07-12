###############################################################################
# OpenVAS Vulnerability Test
# $Id: gallarific_28163.nasl 10698 2018-08-01 07:20:28Z cfischer $
#
# Gallarific Cross Site Scripting and Authentication Bypass Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100309");
  script_version("$Revision: 10698 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-01 09:20:28 +0200 (Wed, 01 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-10-20 18:54:22 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-1326");
  script_bugtraq_id(28163);
  script_name("Gallarific Cross Site Scripting and Authentication Bypass Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28163");
  script_xref(name:"URL", value:"http://www.gallarific.com/download.php");

  script_tag(name:"summary", value:"Gallarific is prone to a cross-site scripting vulnerability and
  multiple authentication-bypass vulnerabilities.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site, steal cookie-based
  authentication credentials, add new categories, add new users, and modify existing users. Other attacks
  are also possible.");

  script_tag(name:"affected", value:"These issues affect both the commercial and the free versions of
  Gallarific.");

  script_tag(name:"solution", value:"Updates are available. Please contact the vendor for details.");

  script_tag(name:"qod", value:"50"); # No extra check, prone to false positives and doesn't match existing qod_types
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/photos", "/gallery", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url =  dir + '/search.php?dosearch=true&query="><script>alert(document.cookie)</script>';
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( isnull( buf ) ) continue;

  if( buf =~ "^HTTP/1\.[01] 200" && egrep( pattern:"<script>alert\(document\.cookie\)</script>", string:buf, icase:TRUE ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
