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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147682");
  script_version("2022-02-23T03:03:33+0000");
  script_tag(name:"last_modification", value:"2022-02-23 11:20:38 +0000 (Wed, 23 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-22 06:49:13 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-03 15:46:00 +0000 (Thu, 03 Feb 2022)");

  script_cve_id("CVE-2022-23968");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Xerox Printers DoS Vulnerability (XRX22-002)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_xerox_printer_consolidation.nasl");
  script_mandatory_keys("xerox/printer/detected");

  script_tag(name:"summary", value:"Multiple Xerox printers are prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"Xerox devices allow remote attackers to brick the device via a
  crafted TIFF file in an unauthenticated HTTP POST request. There is a permanent denial of service
  because image parsing causes a reboot, but image parsing is restarted as soon as the boot process
  finishes. However, this boot loop can be resolved by a field technician. The TIFF file must have
  an incomplete Image Directory.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://security.business.xerox.com/wp-content/uploads/2022/01/Xerox-Security-Bulletin-XRX22-002-for-CVE-2022-23968.pdf");
  script_xref(name:"URL", value:"https://neosmart.net/blog/2022/xerox-vulnerability-allows-unauthenticated-network-users-to-remotely-brick-printers/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:xerox:phaser_6510_firmware",
                     "cpe:/o:xerox:phaser_6510dn_firmware",
                     "cpe:/o:xerox:workcentre_6515_firmware",
                     "cpe:/o:xerox:workcentre_6515dn_firmware",
                     "cpe:/o:xerox:versalink_b400_firmware",
                     "cpe:/o:xerox:versalink_b400dn_firmware",
                     "cpe:/o:xerox:versalink_b405_firmware",
                     "cpe:/o:xerox:versalink_b405dn_firmware",
                     "cpe:/o:xerox:versalink_b600_firmware",
                     "cpe:/o:xerox:versalink_b600x_firmware",
                     "cpe:/o:xerox:versalink_b605_firmware",
                     "cpe:/o:xerox:versalink_b605x_firmware",
                     "cpe:/o:xerox:versalink_b610_firmware",
                     "cpe:/o:xerox:versalink_b610xl_firmware",
                     "cpe:/o:xerox:versalink_b615_firmware",
                     "cpe:/o:xerox:versalink_b615xl_firmware",
                     "cpe:/o:xerox:versalink_b7025_firmware",
                     "cpe:/o:xerox:versalink_b7030_firmware",
                     "cpe:/o:xerox:versalink_b7035_firmware",
                     "cpe:/o:xerox:versalink_c400_firmware",
                     "cpe:/o:xerox:versalink_c400dn_firmware",
                     "cpe:/o:xerox:versalink_c405_firmware",
                     "cpe:/o:xerox:versalink_c405dn_firmware",
                     "cpe:/o:xerox:versalink_c500_firmware",
                     "cpe:/o:xerox:versalink_c500x_firmware",
                     "cpe:/o:xerox:versalink_c505_firmware",
                     "cpe:/o:xerox:versalink_c505x_firmware",
                     "cpe:/o:xerox:versalink_c600_firmware",
                     "cpe:/o:xerox:versalink_c600x_firmware",
                     "cpe:/o:xerox:versalink_c605_firmware",
                     "cpe:/o:xerox:versalink_c605x_firmware",
                     "cpe:/o:xerox:versalink_c7000_firmware",
                     "cpe:/o:xerox:versalink_c7020_firmware",
                     "cpe:/o:xerox:versalink_c7025_firmware",
                     "cpe:/o:xerox:versalink_c7030_firmware",
                     "cpe:/o:xerox:versalink_c8000_firmware",
                     "cpe:/o:xerox:versalink_c9000_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = infos["version"];

if (version_is_less(version: version, test_version: "1.61.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.61.23");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
