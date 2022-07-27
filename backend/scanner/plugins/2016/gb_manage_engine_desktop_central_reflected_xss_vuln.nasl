###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manage_engine_desktop_central_reflected_xss_vuln.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# Manage Engine Desktop Central Reflected Cross Site Scripting Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH http://www.greenbone.net
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

CPE = "cpe:/a:zohocorp:manageengine_desktop_central";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807741");
  script_version("$Revision: 14181 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-04-19 12:07:40 +0530 (Tue, 19 Apr 2016)");

  script_name("Manage Engine Desktop Central Reflected Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with ManageEngine
  Desktop Central and is prone to reflected cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as input passed via 'To'
  parameter of 'Specify Delivery Format' is not validated properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to cause cross site scripting and steal the cookie of other active sessions.");

  script_tag(name:"affected", value:"ManageEngine Desktop Central version 9.1.0
  Build 91099.");

  script_tag(name:"solution", value:"Upgrade to ManageEngine Desktop Central version
  92026 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136463");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_desktop_central_detect.nasl");
  script_mandatory_keys("ManageEngine/Desktop_Central/installed");
  script_require_ports("Services/www", 8040);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!mePort = get_app_port(cpe:CPE))
  exit(0);

if (!meVer = get_app_version(cpe:CPE, port:mePort))
  exit(0);

if (version_is_equal(version:meVer, test_version:"91099")) {
  report = report_fixed_ver(installed_version:meVer, fixed_version:"92026");
  security_message(data:report, port:mePort);
  exit(0);
}

exit(99);