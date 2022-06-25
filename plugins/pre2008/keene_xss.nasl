###############################################################################
# OpenVAS Vulnerability Test
# $Id: keene_xss.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Keene digital media server XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
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

# Ref: Dr_insane

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14681");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(11111);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Keene digital media server XSS");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software.");

  script_tag(name:"summary", value:"The remote host runs Keene digital media server, a webserver
  used to share digital information.

  This version is vulnerable to multiple cross-site scripting attacks which
  may allow an attacker to steal the cookies of users of this site.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

urls = make_list(
"/dms/slideshow.kspx?source=<script>foo</script>",
"/dms/dlasx.kspx?shidx=<script>foo</script>",
"/igen/?pg=dlasx.kspx&shidx=<script>foo</script>",
"/dms/mediashowplay.kspx?pic=<script>foo</script>&idx=0",
"/dms/mediashowplay.kspx?pic=0&idx=<script>foo</script>"
 );

port = get_http_port( default:80 );
host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach url( urls ) {

  buf = http_get( item:url, port:port );
  r = http_keepalive_send_recv( port:port, data:buf, bodyonly:FALSE );
  if(!r) exit( 0 );

  if( r =~ "^HTTP/1\.[01] 200" && "<script>foo</script>" >< r ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );