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
  script_oid("1.3.6.1.4.1.25623.1.0.142513");
  script_version("2019-06-28T06:19:27+0000");
  script_tag(name:"last_modification", value:"2019-06-28 06:19:27 +0000 (Fri, 28 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-28 03:20:03 +0000 (Fri, 28 Jun 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-6323", "CVE-2019-6324", "CVE-2019-6325", "CVE-2019-6326", "CVE-2019-6327");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP LaserJet Pro Multiple Vulnerabilities (HPSBPI03619)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_printer_detect.nasl");
  script_mandatory_keys("hp_printer/installed");

  script_tag(name:"summary", value:"Certain HP LaserJet Pro printers are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - Multiple XSS vulnerabilities (CVE-2019-6323, CVE-2019-6324)

  - A CSRF vulnerability (CVE-2019-6325)

  - Multiple buffer overflow vulnerabilities (CVE-2019-6326, CVE-2019-6327)");

  script_tag(name:"affected", value:"HP Color LaserJet Pro M280-M281 Multifunction Printer series and
  HP LaserJet Pro MFP M28-M31 Printer series.");

  script_tag(name:"solution", value:"Update to firmware version 20190419 (LaserJet Pro M280-M281), 20190426
  (LaserJet Pro MFP M28-M31) or later.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/c06356322");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_pref = 'cpe:/h:hp:laserjet_mfp_m28';

if (!infos = get_app_port_from_cpe_prefix(cpe: cpe_pref, first_cpe_only: TRUE)) {
  cpe_pref = 'cpe:/h:hp:laserjet_mfp_m3';
  if (!infos = get_app_port_from_cpe_prefix(cpe: cpe_pref, first_cpe_only: TRUE))
    exit(0);
}

cpe = infos['cpe'];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe =~ "^cpe:/h:hp:laserjet_mfp_m28[01]") {
  if (version_is_less(version: version, test_version: "20190419")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "20190419");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/h:hp:laserjet_mfp_m(28|29|30|31)[a-z]") {
  if (version_is_less(version: version, test_version: "20190426")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "20190426");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
