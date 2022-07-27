# OpenVAS Vulnerability Test
# $Id: oscommerce_session_id_xss.nasl 13975 2019-03-04 09:32:08Z cfischer $
# Description: osCommerce Malformed Session ID XSS Vulnerability
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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


# From: JeiAr [security@gulftech.org]
# Subject: osCommerce Malformed Session ID XSS Vuln
# Date: Wednesday 17/12/2003 19:59

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11958");
  script_version("$Revision: 13975 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2003-1219");
  script_bugtraq_id(9238);
  script_name("osCommerce Malformed Session ID XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("oscommerce_detect.nasl");
  script_require_keys("Software/osCommerce");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Update to osCommerce 2.2 Milestone 3 or later which will redirect the user
  to the index page when a malformed session ID is used, so that a new session ID can be generated.");

  script_tag(name:"summary", value:"osCommerce is vulnerable to a XSS flaw. The flaw can be exploited when a
  malicious user passes a malformed session ID to URI.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

CPE = 'cpe:/a:oscommerce:oscommerce';

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

quote = raw_string(0x22);

url = string(dir, "?osCsid=%22%3E%3Ciframe%20src=foo%3E%3C/iframe%3E");
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if(!res)
  exit(0);

find = string("\\?osCsid=", quote, "><iframe src=foo></iframe>");
if(egrep(pattern:find, string:res) && ("Powered by" >< res) && ("osCommerce" >< res)) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);