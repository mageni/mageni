###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tikiwiki_url_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# TikiWiki URL Multilple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802353");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-4454", "CVE-2011-4455");
  script_bugtraq_id(50683);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-06 16:09:33 +0530 (Tue, 06 Dec 2011)");
  script_name("Tiki Wiki CMS Groupware URL Multilple Cross-Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TikiWiki/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46740/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107002/sa46740.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107082/INFOSERVE-ADV2011-01.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");
  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware Version 8.0.RC1 and prior.");
  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of input appended to
  the URL via pages 'tiki-remind_password.php', 'tiki-index.php',
  'tiki-login_scr.php', 'tiki-admin_system.php', 'tiki-pagehistory.php' and
  'tiki-removepage.php', That allows attackers to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");
  script_tag(name:"solution", value:"Upgrade Tiki Wiki CMS Groupware to 8.1 or later");
  script_tag(name:"summary", value:"The host is running Tiki Wiki CMS Groupware and is prone to multiple cross site
  scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://info.tiki.org/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

foreach page( make_list( "/tiki-index.php", "/tiki-admin_system.php",
                         "/tiki-pagehistory.php", "/tiki-login_scr.php" ) ) {

  url = dir + page + '/%22%20onmouseover=%22alert(document.cookie)%22';

  if( http_vuln_check( port:port, url:url, pattern:'php/" onmouseover="alert\\(document\\.cookie\\)"', check_header:TRUE ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );