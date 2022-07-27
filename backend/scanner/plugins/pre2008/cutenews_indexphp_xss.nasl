###############################################################################
# OpenVAS Vulnerability Test
# $Id: cutenews_indexphp_xss.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# CuteNews index.php XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
###############################################################################

CPE = "cpe:/a:cutephp:cutenews";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14665");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1659");
  script_bugtraq_id(11097);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("CuteNews index.php XSS");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("cutenews_detect.nasl", "cross_site_scripting.nasl");
  script_mandatory_keys("cutenews/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=109415338521881&w=2");

  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_tag(name:"summary", value:"The version of CuteNews installed on the remote host is
  vulnerable to a cross-site-scripting (XSS) attack.");

  script_tag(name:"impact", value:"An attacker, exploiting this flaw, would need to be able to
  coerce a user to browse to a purposefully malicious URI. Upon successful exploitation, the attacker
  would be able to run code within the web-browser in the security context of the CuteNews server.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

url = dir + "/index.php?mod=<script>foo</script>";
req = http_get(item: url, port: port);
r = http_keepalive_send_recv(port: port, data: req);
if( ! r ) exit( 0 );

if (r =~ "^HTTP/1\.[01] 200" && egrep(pattern:"<script>foo</script>", string:r)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
}

exit(0);