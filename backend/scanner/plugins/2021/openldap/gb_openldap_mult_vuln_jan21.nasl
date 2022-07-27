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
  script_oid("1.3.6.1.4.1.25623.1.0.146991");
  script_version("2021-10-27T14:04:00+0000");
  script_tag(name:"last_modification", value:"2021-10-27 14:04:00 +0000 (Wed, 27 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-27 08:22:43 +0000 (Wed, 27 Oct 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)");

  script_cve_id("CVE-2020-36221", "CVE-2020-36222", "CVE-2020-36223", "CVE-2020-36224",
                "CVE-2020-36225", "CVE-2020-36226", "CVE-2020-36227", "CVE-2020-36228",
                "CVE-2020-36229", "CVE-2020-36230");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenLDAP < 2.4.57 Multiple DoS Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openldap_consolidation.nasl");
  script_mandatory_keys("openldap/detected");

  script_tag(name:"summary", value:"OpenLDAP is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-36221: Integer underflow leading to slapd crashes in the Certificate Exact Assertion
  processing

  - CVE-2020-36222: Assertion failure in slapd in the saslAuthzTo validation

  - CVE-2020-36223: slapd crash in the Values Return Filter control handling

  - CVE-2020-36224: Invalid pointer free and slapd crash in the saslAuthzTo processing

  - CVE-2020-36225: Double free and slapd crash in the saslAuthzTo processing

  - CVE-2020-36226: memch->bv_len miscalculation and slapd crash in the saslAuthzTo processing

  - CVE-2020-36227: Infinite loop in slapd with the cancel_extop Cancel operation

  - CVE-2020-36228: Integer underflow leading to a slapd crash in the Certificate List Exact
  Assertion processing

  - CVE-2020-36229: slapd crash in the X.509 DN parsing in ad_keystring

  - CVE-2020-36230: Assertion failure in slapd in the X.509 DN parsing in decode.c ber_next_element");

  script_tag(name:"affected", value:"OpenLDAP prior to version 2.4.57.");

  script_tag(name:"solution", value:"Update to version 2.4.57 or later.");

  script_xref(name:"URL", value:"https://bugs.openldap.org/show_bug.cgi?id=9404");
  script_xref(name:"URL", value:"https://bugs.openldap.org/show_bug.cgi?id=9406");
  script_xref(name:"URL", value:"https://bugs.openldap.org/show_bug.cgi?id=9408");
  script_xref(name:"URL", value:"https://bugs.openldap.org/show_bug.cgi?id=9409");
  script_xref(name:"URL", value:"https://bugs.openldap.org/show_bug.cgi?id=9412");
  script_xref(name:"URL", value:"https://bugs.openldap.org/show_bug.cgi?id=9413");
  script_xref(name:"URL", value:"https://bugs.openldap.org/show_bug.cgi?id=9428");
  script_xref(name:"URL", value:"https://bugs.openldap.org/show_bug.cgi?id=9427");
  script_xref(name:"URL", value:"https://bugs.openldap.org/show_bug.cgi?id=9425");
  script_xref(name:"URL", value:"https://bugs.openldap.org/show_bug.cgi?id=9423");

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

if (version_is_less(version: version, test_version: "2.4.57")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.57", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
