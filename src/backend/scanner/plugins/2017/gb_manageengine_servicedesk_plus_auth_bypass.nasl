##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_servicedesk_plus_auth_bypass.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# ManageEngine ServiceDesk Plus Authentication Bypass Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:manageengine:servicedesk_plus";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106819");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-22 16:23:48 +0700 (Mon, 22 May 2017)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ManageEngine ServiceDesk Plus Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ManageEngine_ServiceDesk_Plus_detect.nasl");
  script_mandatory_keys("ManageEngine/ServiceDeskPlus/installed");

  script_tag(name:"summary", value:"ManageEngine ServiceDesk Plus is prone to an authentication bypass
vulnerability.");

  script_tag(name:"insight", value:"A valid username can be used as both username/password to login and
compromise the application through the /mc directory which is the mobile client directory. This can be achieved
ONLY if Active Directory/LDAP is being used.

This flaw exists because of the lack of password randomization in the application version 9.0.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"ManageEngine ServiceDesk Plus prior version 9.2 build 9241");

  script_tag(name:"solution", value:"Upgrade to version 9.2 build 9241 or later.");

  script_xref(name:"URL", value:"https://www.manageengine.com/products/service-desk/readme-9.2.html");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/142598/ManageEngine-ServiceDesk-Plus-9.0-Authentication-Bypass.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

version = str_replace(string: version, find: "build", replace: ".");

if (version_is_less(version: version, test_version: "9.2.9241")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2 Build 9241");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
