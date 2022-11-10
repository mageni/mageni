# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.118410");
  script_version("2022-11-09T14:13:24+0000");
  script_tag(name:"last_modification", value:"2022-11-09 14:13:24 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-09 12:53:13 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2022-25313", "CVE-2022-25314", "CVE-2022-25315", "CVE-2022-25235",
                "CVE-2022-25236", "CVE-2022-23990", "CVE-2022-23852");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus < 8.15.5 Multiple Vulnerabilities (TNS-2022-12)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_mandatory_keys("nessus/installed");

  script_tag(name:"summary", value:"Tenable Nessus is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nessus leverages third-party software to help provide underlying
  functionality. One of the third-party components (Expat) was found to contain vulnerabilities, and
  an updated version has been made available by the provider.

  Nessus 8.15.5 updates Expat to version 2.4.8 to address the identified vulnerabilities.");

  script_tag(name:"affected", value:"Tenable Nessus prior to version 8.15.5.");

  script_tag(name:"solution", value:"Update to version 8.15.5 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2022-12");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "8.15.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.15.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
