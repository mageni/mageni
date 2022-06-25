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

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144316");
  script_version("2020-07-27T03:10:51+0000");
  script_tag(name:"last_modification", value:"2020-07-27 09:32:59 +0000 (Mon, 27 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-27 03:02:27 +0000 (Mon, 27 Jul 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2020-5765");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus < 8.11.0 XSS Vulnerability (TNS-2020-05)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_mandatory_keys("nessus/installed");

  script_tag(name:"summary", value:"Tenable Nessus is prone to a stored cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nessus is prone a stored XSS vulnerability due to improper validation of input
  during scan configuration.");

  script_tag(name:"impact", value:"An authenticated, remote attacker could potentially exploit this vulnerability
  to execute arbitrary code in a user's session.");

  script_tag(name:"affected", value:"Tenable Nessus version 8.10.0 and prior.");

  script_tag(name:"solution", value:"Update to version 8.11.0 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2020-05");

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

if (version_is_less(version: version, test_version: "8.11.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.11.0", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
