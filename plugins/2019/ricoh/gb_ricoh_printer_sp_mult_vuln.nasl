# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142830");
  script_version("2019-09-03T07:07:25+0000");
  script_tag(name:"last_modification", value:"2019-09-03 07:07:25 +0000 (Tue, 03 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-02 05:05:09 +0000 (Mon, 02 Sep 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-14300", "CVE-2019-14305", "CVE-2019-14307", "CVE-2019-14308");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("RICOH Printers Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ricoh_printer_consolidation.nasl");
  script_mandatory_keys("ricoh_printer/detected");

  script_tag(name:"summary", value:"RICOH printers and multifunction printers are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"RICOH printers and multifunction printers are prone to multiple vulnerabilities:

  - Multiple buffer overflows parsing HTTP cookie headers (CVE-2019-14300)

  - Multiple buffer overflows parsing HTTP parameter settings for Wi-Fi, mDNS, POP3, SMTP, and notification alerts
    (CVE-2019-14305)

  - Multiple buffer overflows parsing HTTP parameter settings for SNMP (CVE-2019-14307)

  - Multiple buffer overflows parsing LPD packets (CVE-2019-14308)");

  script_tag(name:"impact", value:"An attacker may cause a denial of service or code execution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"RICOH SP C250SF and SP C252SF before firmware version 1.13 and RICOH
  SP C250DN and SP C252DN before firmware version 1.07.");

  script_tag(name:"solution", value:"Update firmware to version 1.13 (SP C250SF and SP C252SF), 1.07 (SP C250DN
  and SP C252DN) or later.");

  script_xref(name:"URL", value:"https://www.ricoh.com/info/2019/0823_1/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_array("cpe:/o:ricoh:sp_c250sf_firmware", "1.13",
                      "cpe:/o:ricoh:sp_c252sf_firmware", "1.13",
                      "cpe:/o:ricoh:sp_c250dn_firmware", "1.07",
                      "cpe:/o:ricoh:sp_c252dn_firmware", "1.07");

foreach cpe (keys(cpe_list)) {
  if (!version = get_app_version(cpe: cpe, nofork: TRUE))
    continue;

  fix = cpe_list[cpe];
  if (!fix)
    continue;

  if (version_is_less(version: version, test_version: fix)) {
    report = report_fixed_ver(installed_version: version, fixed_version: fix);
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
