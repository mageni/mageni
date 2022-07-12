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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.#

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144909");
  script_version("2020-11-10T09:13:10+0000");
  script_tag(name:"last_modification", value:"2020-11-11 11:10:35 +0000 (Wed, 11 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-10 09:04:15 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2020-26162");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Xerox WorkCentre EC7836/EC7856 XSS Vulnerability (XRX19Y)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xerox_printer_consolidation.nasl");
  script_mandatory_keys("xerox_printer/detected");

  script_tag(name:"summary", value:"Xerox WorkCentre EC7836/EC7856 printers are prone to a cross-site
  scripting (XSS) vulnerability via Description pages.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"affected", value:"Xerox WorkCentre EC7836 and EC7856 devices.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://securitydocs.business.xerox.com/wp-content/uploads/2019/09/cert_Security_Mini_Bulletin_XRX19Y_for_WorkCentre-EC7836-EC7856.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:xerox:workcentre_ec7836_firmware",
                     "cpe:/o:xerox:workcentre_ec7856_firmware");

if (!infos = get_app_port_from_list(cpe_list: cpe_list))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/o:xerox:workcentre_ec7836_firmware") {
  if (version_is_less(version: version, test_version: "073.050.059.25300")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.050.059.25300");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_ec7856_firmware") {
  if (version_is_less(version: version, test_version: "073.020.059.25300")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.020.059.25300");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
