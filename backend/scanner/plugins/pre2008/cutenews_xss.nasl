###############################################################################
# OpenVAS Vulnerability Test
# $Id: cutenews_xss.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# CuteNews XSS
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
  script_oid("1.3.6.1.4.1.25623.1.0.14318");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10948);
  script_cve_id("CVE-2004-0660");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CuteNews XSS");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");

  script_copyright("This script is Copyright (C) 2004 David Maciejak");

  script_family("Web application abuses");
  script_dependencies("cutenews_detect.nasl", "cross_site_scripting.nasl");
  script_mandatory_keys("cutenews/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Upgrade to CuteNews v1.3.2 or newer.");

  script_tag(name:"summary", value:"The remote web server contains a PHP script that is prone to cross-site
scripting attacks.

Description :

According to it's banner, the version of CuteNews on the remote host fails to sanitize input to the 'archive'
parameter of the 'show_archives.php' script. An attacker, exploiting this flaw, would need to be able to coerce a
user to browse to a purposefully malicious URI. Upon successful exploitation, the attacker would be able to run
code within the web-browser in the security context of the CuteNews server.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/12260/");

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

req = http_get(item:string(dir, "/show_archives.php?archive=<script>foo</script>&subaction=list-archive&"),
 	       port:port);
r = http_keepalive_send_recv(port:port, data:req);
if( isnull( r ) ) exit( 0 );
if(r =~ "^HTTP/1\.[01] 200" && "<script>foo</script>" >< r) {
  security_message(port);
  exit(0);
}

exit(99);
