###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tiki_43507.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Tiki Wiki CMS Groupware Local File Include and Cross Site Scripting Vulnerabilities
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

CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100825");
  script_version("$Revision: 13960 $");
  script_bugtraq_id(43507);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-09-28 17:11:37 +0200 (Tue, 28 Sep 2010)");
  script_name("Tiki Wiki CMS Groupware Local File Include and Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TikiWiki/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43507");
  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/Tiki.Wiki.CMS.Groupware.5.2.Local.File.Inclusion/46");
  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/Tiki.Wiki.CMS.Groupware.5.2.Reflected.Cross-site.Scripting/44");
  script_xref(name:"URL", value:"http://www.tiki.org");

  script_tag(name:"impact", value:"An attacker can exploit the local file-include vulnerability using
  directory-traversal strings to view and execute local files within
  the context of the webserver process. Information harvested may aid
  in further attacks.

  The attacker may leverage the cross-site scripting issue to execute
  arbitrary script code in the browser of an unsuspecting user in the
  context of the affected site. This may let the attacker steal cookie-
  based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware 5.2 is vulnerable. Other versions may also
  be affected.");

  script_tag(name:"solution", value:"Upgrade to latest version");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to a local file-include vulnerability
  and a cross-site scripting vulnerability because it fails to properly
  sanitize user-supplied input.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

url = dir + "/tiki-edit_wiki_section.php?type=%22%3E%3Cscript%3Ealert(%27vt-xss-test%27)%3C/script%3E";

if( http_vuln_check( port:port, url:url, pattern:"<script>alert\('vt-xss-test'\)</script>", check_header:TRUE ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );