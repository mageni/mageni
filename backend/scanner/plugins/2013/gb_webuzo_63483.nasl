###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webuzo_63483.nasl 14186 2019-03-14 13:57:54Z cfischer $
#
# Webuzo Cookie Value Handling Remote Command Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@igreenbone.net>
#
# Updated By Shashi Kiran N <nskiran@secpod.com> on 2013-11-27
# Added CVE and BID
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:softaculous:webuzo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103831");
  script_bugtraq_id(63483, 63480);
  script_cve_id("CVE-2013-6041", "CVE-2013-6042", "CVE-2013-6043");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 14186 $");

  script_name("Webuzo Cookie Value Handling Remote Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63483");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:57:54 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-11-13 18:18:47 +0100 (Wed, 13 Nov 2013)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_webuzo_detect.nasl");
  script_require_ports("Services/www", 2002, 2004);
  script_mandatory_keys("webuzo/installed");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to execute arbitrary commands
  in the context of the affected application.");

  script_tag(name:"vuldetect", value:"Check the installed version.");

  script_tag(name:"insight", value:"The value of a cookie used by the application is not
  appropriately validated or sanitised before processing and permits backtick
  characters. This allows additional OS commands to be injected and executed on
  the server system, and may result in server compromise.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Webuzo is prone to a remote command-injection vulnerability because it
  fails to adequately sanitize user-supplied input.");

  script_tag(name:"affected", value:"Webuzo <= 2.1.3 is vulnerable. Other versions may also be affected.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(vers = get_app_version(cpe:CPE, port:port)) {

  if(version_is_less_equal(version: vers, test_version: "2.1.3")) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);