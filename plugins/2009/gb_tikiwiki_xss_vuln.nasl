###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tikiwiki_xss_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Tiki Wiki CMS Groupware Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800266");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-04-16 16:39:16 +0200 (Thu, 16 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-1204");
  script_bugtraq_id(34105, 34106, 34107, 34108);
  script_name("Tiki Wiki CMS Groupware Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TikiWiki/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject arbitrary HTML
  codes in the context of the affected web application.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware version 2.2, 2.3 and prior.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper sanitization of user supplied input in
  the pages i.e. 'tiki-orphan_pages.php', 'tiki-listpages.php',
  'tiki-list_file_gallery.php' and 'tiki-galleries.php' which lets the attacker
  conduct XSS attacks inside the context of the web application.");

  script_tag(name:"solution", value:"Upgrade to Tiki Wiki CMS Groupware version 2.4 or later.");

  script_tag(name:"summary", value:"This host is running Tiki Wiki CMS Groupware and is prone to Multiple Cross Site Scripting
  vulnerabilities.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34273");
  script_xref(name:"URL", value:"http://info.tikiwiki.org/tiki-read_article.php?articleId=51");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" ) dir = "";

# Multiple XSS attempts
urls = make_list( dir + '/tiki-listpages.php/<script>alert("XSS_Check");</script>',
                  dir + '/tiki-galleries.php/<script>alert("XSS_Check");</script>',
                  dir + '/tiki-orphan_pages.php/<script>alert("XSS_Check");</script>',
                  dir + '/tiki-list_file_gallery.php/<script>alert("XSS_Check");</script>' );

foreach url( urls ) {
  if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:'<script>alert\\("XSS_Check"\\);</script>' ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );