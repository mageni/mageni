###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_scoreboard_sec_bypass_vuln_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Apache HTTP Server Scoreboard Security Bypass Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803744");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2012-0031");
  script_bugtraq_id(51407);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-08-21 19:53:07 +0530 (Wed, 21 Aug 2013)");
  script_name("Apache HTTP Server Scoreboard Security Bypass Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is running Apache HTTP Server and is prone to security bypass
vulnerability.");
  script_tag(name:"vuldetect", value:"Get the installed version Apache HTTP Server with the help of detect NVT
and check it is vulnerable or not.");
  script_tag(name:"solution", value:"Upgrade to Apache HTTP Server 2.2.22 or later.");
  script_tag(name:"insight", value:"The flaw is due to an error in 'inscoreboard.c', certain type field within
a scoreboard shared memory segment leading to an invalid call to the free
function.");
  script_tag(name:"affected", value:"Apache HTTP Server version before 2.2.22 on windows.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to bypass certain security
restrictions. Other attacks are also possible.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1230065");
  script_xref(name:"URL", value:"http://www.halfdog.net/Security/2011/ApacheScoreboardInvalidFreeOnShutdown");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/installed", "Host/runs_windows");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!httpPort = get_app_port(cpe:CPE)) exit(0);
if(!httpVers = get_app_version(cpe:CPE, port:httpPort)) exit(0);

if(version_is_less(version:httpVers, test_version:"2.2.22"))
{
  security_message(port:httpPort);
  exit(0);
}
