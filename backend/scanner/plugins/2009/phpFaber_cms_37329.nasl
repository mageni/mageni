###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpFaber_cms_37329.nasl 14332 2019-03-19 14:22:43Z asteins $
#
# phpFaber CMS 'module.php' Cross Site Scripting Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100401");
  script_version("$Revision: 14332 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:22:43 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-12-16 12:39:06 +0100 (Wed, 16 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4382");
  script_bugtraq_id(37329);
  script_name("phpFaber CMS 'module.php' Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37329");
  script_xref(name:"URL", value:"http://www.phpfaber.com/i/products/cms/");

  script_tag(name:"summary", value:"phpFaber CMS is prone to a cross-site scripting vulnerability because
  it fails to properly sanitize user-supplied input.");
  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/cms", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/module.php?mod=<script>alert(8154711)</script>";

  if( http_vuln_check( port:port, url:url, pattern:"<code>Module '<script>alert\(8154711\)</script>' not found</code>", check_header:TRUE ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
