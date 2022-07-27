# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:openldap:openldap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146992");
  script_version("2021-10-27T14:04:00+0000");
  script_tag(name:"last_modification", value:"2021-10-27 14:04:00 +0000 (Wed, 27 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-27 09:17:54 +0000 (Wed, 27 Oct 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 11:15:00 +0000 (Fri, 16 Jul 2021)");

  script_cve_id("CVE-2020-25709", "CVE-2020-25710");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenLDAP < 2.4.56 Multiple DoS Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openldap_consolidation.nasl");
  script_mandatory_keys("openldap/detected");

  script_tag(name:"summary", value:"OpenLDAP is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-25709: An attacker who can send a malicious packet to be processed by OpenLDAP's slapd
  server may trigger an assertion failure

  - CVE-2020-25710: An attacker who sends a malicious packet processed by OpenLDAP may force a
  failed assertion in csnNormalize23()");

  script_tag(name:"affected", value:"OpenLDAP prior to version 2.4.56.");

  script_tag(name:"solution", value:"Update to version 2.4.56 or later.");

  script_xref(name:"URL", value:"https://lists.openldap.org/hyperkitty/list/openldap-announce@openldap.org/thread/K6L6NCCOLWK5CZLB6KC2F6TD2Z5JAU7E/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2.4.56")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.56", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
