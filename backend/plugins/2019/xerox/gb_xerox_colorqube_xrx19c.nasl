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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.#

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142318");
  script_version("2019-04-29T14:03:34+0000");
  script_tag(name:"last_modification", value:"2019-04-29 14:03:34 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-29 13:43:04 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2019-10880");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Xerox ColorQube Printers RCE Vulnerability (XRX19C)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_xerox_printer_consolidation.nasl");
  script_mandatory_keys("xerox_printer/detected", "xerox_printer/fw_version");

  script_tag(name:"summary", value:"Xerox ColorQube printers are prone to a remote code execution vulnerability.");

  script_tag(name:"insight", value:"Within multiple XEROX products a vulnerability allows remote command execution
  on the Linux system, as the 'nobody' user through a crafted HTTP request (OS Command Injection vulnerability in
  the HTTP interface). Depending upon configuration authentication may not be necessary.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"affected", value:"Xerox ColorQube 8700, 8900, 9301, 9302 and 9303.");

  script_tag(name:"solution", value:"Update the firmware to version 072.161.009.07200 (8700 and 8900 series),
  072.180.009.07200 (9301/9302/9303 series) or later.");

  script_xref(name:"URL", value:"https://securitydocs.business.xerox.com/wp-content/uploads/2019/04/cert_Security_Mini_Bulletin_XRX19C_for_CQ8700_CQ8900_CQ93xx.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!model = get_kb_item("xerox_printer/model"))
  exit(0);

if (model !~ "^ColorQube (8700|8900|9301|9302|9303)")
  exit(0);

if (!fw = get_kb_item("xerox_printer/fw_version"))
  exit(0);

if (model =~ "^ColorQube (87|89)") {
  if (version_is_less(version: fw, test_version: "072.161.009.07200")) {
    report = report_fixed_ver(installed_version: fw, fixed_version: "072.161.009.07200");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else {
  if (version_is_less(version: fw, test_version: "072.180.009.07200")) {
    report = report_fixed_ver(installed_version: fw, fixed_version: "072.180.009.07200");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
