##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manage_engine_opmanager_mult_vuln.nasl 13755 2019-02-19 10:42:02Z jschulte $
#
# ManageEngine OpManager Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = 'cpe:/a:zohocorp:manageengine_opmanager';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106093");
  script_version("$Revision: 13755 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-19 11:42:02 +0100 (Tue, 19 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-06-06 16:31:30 +0700 (Mon, 06 Jun 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ManageEngine OpManager Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_opmanager_consolidation.nasl");
  script_mandatory_keys("manageengine/opmanager/detected");

  script_tag(name:"summary", value:"ManageEngine OpManager is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple XSS and CSRF vulnerabilities were found in ManageEngine
OpManager.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
arbitrary script code.");

  script_tag(name:"affected", value:"Versions prior to v12");

  script_tag(name:"solution", value:"Upgrade to Version 12 or later");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2016/Jun/12");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
