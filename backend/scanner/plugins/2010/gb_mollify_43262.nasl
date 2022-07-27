###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mollify_43262.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# Mollify 'index.php' Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100806");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-09-16 16:08:48 +0200 (Thu, 16 Sep 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-3462");
  script_bugtraq_id(43262);

  script_name("Mollify 'index.php' Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43262");
  script_xref(name:"URL", value:"http://www.mollify.org/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"Mollify is prone to a cross-site scripting vulnerability because it
fails to sufficiently sanitize user-supplied data.

An attacker may leverage this issue to execute arbitrary JavaScript
code in the browser of an unsuspecting user in the context of the
affected site. This may allow the attacker to steal cookie-based
authentication credentials and to launch other attacks.

Mollify 1.6 is vulnerable, other versions may also be affected.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/mollify", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir,"/backend/plugin/Registration/index.php?confirm=%3Cscript%3Ealert(%27openvas-xss-test%27)%3C/script%3E");

  if(http_vuln_check(port:port, url:url,pattern:"<script>alert\('openvas-xss-test'\)</script>",check_header:TRUE,extra_check:"Confirmation")) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
