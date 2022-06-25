# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:tibco:jasperreports_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143999");
  script_version("2020-05-28T05:35:44+0000");
  script_tag(name:"last_modification", value:"2020-05-28 05:35:44 +0000 (Thu, 28 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-28 04:54:38 +0000 (Thu, 28 May 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2020-9409");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TIBCO JasperReports <= 7.1.1 Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jasperreports_detect.nasl");
  script_mandatory_keys("jasperreports/installed");

  script_tag(name:"summary", value:"TIBCO JasperReports is prone to an access control vulnerability in the
  administrative UI component.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"JasperReports contains a vulnerability that theoretically allows an
  unauthenticated attacker to obtain the permissions of a JasperReports Server 'superuser' for the affected
  systems. The attacker can theoretically exploit the vulnerability consistently, remotely, and without
  authenticating.");

  script_tag(name:"impact", value:"An unauthenticated user may obtain JasperReports Server 'superuser'
  permission, and further might be able to execute arbitrary code with the system account that started the
  affected component.");

  script_tag(name:"affected", value:"TIBCO JasperReports Server 7.1.1 and prior.");

  script_tag(name:"solution", value:"Update to version 7.1.3 or later.");

  script_xref(name:"URL", value:"https://www.tibco.com/support/advisories/2020/05/tibco-security-advisory-may-19-2020-tibco-jasperreports-server");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "7.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
