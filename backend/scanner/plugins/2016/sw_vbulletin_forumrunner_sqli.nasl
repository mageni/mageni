###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_vbulletin_forumrunner_sqli.nasl 5850 2017-04-04 09:01:03Z teissa $
#
# vBulletin 3.6.x to 4.2.2/4.2.3 Forumrunner 'request.php' SQL Injection
#
# Authors:
# Christian Fischer <info at schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH
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

CPE = 'cpe:/a:vbulletin:vbulletin';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111112");
  script_version("$Revision: 5850 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-04 11:01:03 +0200 (Tue, 04 Apr 2017) $");
  script_tag(name:"creation_date", value:"2016-07-24 14:00:00 +0200 (Sun, 24 Jul 2016)");
  script_cve_id("CVE-2016-6195");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("vBulletin 3.6.x to 4.2.2/4.2.3 Forumrunner 'request.php' SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vBulletin/installed");

  script_xref(name:"URL", value:"https://enumerated.wordpress.com/2016/07/11/1/");
  script_xref(name:"URL", value:"http://www.vbulletin.com/forum/node/4345175");
  script_xref(name:"URL", value:"http://members.vbulletin.com/patches.php");

  script_tag(name:"solution", value:"The Patches 4.2.2 Patch Level 5 and 4.2.3 Patch Level 1 are available
  at the vBulletin member's area.");
  script_tag(name:"summary", value:"The vBulletin core forumrunner addon (enabled by default)
  is affected by an SQL injection vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow an unauthenticated remote
  attacker to execute arbitrary SQL commands via the 'postids' parameter to request.php.");
  script_tag(name:"affected", value:"vBulletin 3.6.x to 4.2.2 (before Patch Level 5) / 4.2.3 (before Patch Level 1)
  with an enabled forumrunner addon.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check the response.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + "/forumrunner/request.php?cmd=get_spam_data&d=1&postids='1";

if( http_vuln_check( port:port, url:url, pattern:"(database has encountered a problem|image.php\?type=dberror)" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
