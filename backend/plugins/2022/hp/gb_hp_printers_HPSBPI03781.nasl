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

CPE_PREFIX = "cpe:/o:hp:";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147844");
  script_version("2022-03-24T05:12:34+0000");
  script_tag(name:"last_modification", value:"2022-03-24 05:12:34 +0000 (Thu, 24 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-24 03:42:21 +0000 (Thu, 24 Mar 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-24291", "CVE-2022-24292", "CVE-2022-24293");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printer Multiple Vulnerabilities (HPSBPI03781)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Multiple HP printer are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Certain HP Print devices may be vulnerable to potential
  information disclosure, denial of service, or remote code execution.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_5950417-5950443-16");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe =~ "^cpe:/o:hp:color_laserjet_pro_m45[34]" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_pro_mfp_m47[89]" ||
    cpe =~ "^cpe:/o:hp:laserjet_pro_m30[45]" ||
    cpe =~ "^cpe:/o:hp:laserjet_pro_m40[45]" ||
    cpe =~ "^cpe:/o:hp:laserjet_pro_mfp_m42[89]") {
  # e.g. SHMNTOXXXN002.2149A.00
  version = substr(version, 10);
  if (version_is_less(version: version, test_version: "002.2208a")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "002.2208A");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_mfp_m2") {
  report = report_fixed_ver(installed_version: toupper(version), fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

if (cpe =~ "^cpe:/o:hp:pagewide_352dw" ||
    cpe =~ "^cpe:/o:hp:pagewide_377" ||
    cpe =~ "^cpe:/o:hp:pagewide_p55250" ||
    cpe =~ "^cpe:/o:hp:pagewide_mfp_p57750" ||
    cpe =~ "^cpe:/o:hp:pagewide_pro_452d[nw]" ||
    cpe =~ "^cpe:/o:hp:pagewide_pro_477d[nw]" ||
    cpe =~ "^cpe:/o:hp:pagewide_pro_552" ||
    cpe =~ "^cpe:/o:hp:pagewide_pro_577") {
  # e.g. MAVEDWPP1N001.2142A.00
  version = substr(version, 14);
  if (version_is_less(version: version, test_version: "2205d")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "2205D");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:officejet_pro_8210" ||
    cpe =~ "^cpe:/o:hp:officejet_pro_8216") {
  # e.g. TESPDLPP1N001.1919A.00
  version = substr(version, 10);
  if (version_is_less(version: version, test_version: "001.2210b")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "001.2210B");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:officejet_pro_87[34]0") {
  # e.g. WEBPDLPP1N001.1709A.00
  version = substr(version, 10);
  if (version_is_less(version: version, test_version: "001.2207c")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "001.2207C");
    security_message(port: 0, data: report);
    exit(0);
  }
}


exit(99);
