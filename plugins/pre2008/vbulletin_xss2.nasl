###############################################################################
# OpenVAS Vulnerability Test
# $Id: vbulletin_xss2.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# vBulletin XSS(2)
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

#  Ref: Arab VieruZ <arabviersus@hotmail.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14833");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2004-1824");
  script_bugtraq_id(6226);
  script_name("vBulletin XSS(2)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("cross_site_scripting.nasl", "vbulletin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vBulletin/installed");
  script_tag(name:"solution", value:"Upgrade to latest version");
  script_tag(name:"summary", value:"The remote host is running vBulletin, a web based bulletin board system
written in PHP.

The remote version of this software seems to be prior or equal to version 2.2.9.
These versions are vulnerable to a cross-site scripting issue,
due to a failure of the application to properly sanitize user-supplied
URI input.

As a result of this vulnerability, it is possible for a remote attacker
to create a malicious link containing script code that will be executed
in the browser of an unsuspecting user when followed.

This may facilitate the theft of cookie-based authentication credentials
as well as other attacks.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  buf = http_get(item:dir + "/memberlist.php?s=23c37cf1af5d2ad05f49361b0407ad9e&what=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf);
  if( isnull( r ) ) exit( 0 );
  if(r =~ "^HTTP/1\.[01] 200" && egrep(pattern:"<script>foo</script>", string:r)) security_message(port);
}
