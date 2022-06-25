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
  script_oid("1.3.6.1.4.1.25623.1.0.147845");
  script_version("2022-03-30T09:36:52+0000");
  script_tag(name:"last_modification", value:"2022-03-31 10:53:41 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-24 07:29:07 +0000 (Thu, 24 Mar 2022)");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:P");

  script_cve_id("CVE-2022-3942");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printer RCE Vulnerability (HPSBPI03780)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Multiple HP printer are prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Certain HP Print products and Digital Sending products may be
  vulnerable to potential remote code execution and buffer overflow with use of Link-Local
  Multicast Name Resolution or LLMNR.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_5948778-5949142-16/hpsbpi03780");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/o:hp:color_laserjet_cm4540_mfp_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000621")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000621 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_cp5525_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000618")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000618 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m578_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m578_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064712")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064712 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023872")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023872 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m880_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m880_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000589")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000589 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064701")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064701 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_m455_firmware") {
  if (version_is_less(version: version, test_version: "2504171.023889")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023889 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_m552_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000614")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000614 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064715")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064715 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171_023885")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023885 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_m553_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000614")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000614 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064715")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064715 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023885")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023885 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_m55[45]_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064709")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064709 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023885")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023885 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_m651_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000597")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000597 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064706")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064706 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_m65[23]_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064707")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064707 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171_023884")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023884 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_m750_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000608")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000608 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }
}


if (cpe == "cpe:/o:hp:color_laserjet_m751_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_e75245_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064687")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064687 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023884")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023897 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_m855_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000596")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000596 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064685")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064685 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_m856_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064693")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064693 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023901")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023901 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m480_firmware") {
  if (version_is_less(version: version, test_version: "2504171.023869")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023869 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m577_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m577_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000586")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000586 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064715")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064715 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023872")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023872 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m680_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m680_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000602")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000602 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064689")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064689 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_mfp_m68[12]_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_flow_mfp_m68[12]_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064686")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064686 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023881")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023881 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m776_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m776_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064695")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064695 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023880")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023880 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_e45028_firmware") {
  if (version_is_less(version: version, test_version: "2504171.023889")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023889 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_e55040dw_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064709")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064709 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023885")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023885 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_e65[01]50_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_e65[01]60_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064707")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064707 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023884")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023884 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e47528_firmware") {
  if (version_is_less(version: version, test_version: "2504171.023869")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023869 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e57540_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_e57540_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064715")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064715 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023872")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023872 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e67[56][56]0_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_flow_mfp_e67[56][56]0_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064686")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064686 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023881")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023881 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e7742[2-8]_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064678")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064678 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023873")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023873 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e778(22|25|30)_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_flow_mfp_e778(22|25|30)_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064697")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064697 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023888")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023888 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e7822[3-8]_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064678")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064678 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023873")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023873 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e783(23|30)_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064697")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064697 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023888")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023888 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e876[456]0_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_flow_mfp_e876[456]0_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064679")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064679 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023878")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023878 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e876[46]0du_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064679")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064679 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023878")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023878 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:digital_sender_flow_8500_fn2_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064680")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064680 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023867")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023867 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_500_color_mfp_m575_firmware" ||
    cpe == "cpe:/o:hp:laserjet_500_color_flow_mfp_m575_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000598")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000598 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064696")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064696 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_500_color_m551_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000590")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000590 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_500_color_mfp_m525_firmware" ||
    cpe == "cpe:/o:hp:laserjet_500_color_flow_mfp_m525_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000592")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000592 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064710")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064710 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_600_color_m60[123]_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000599")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000599 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_700_color_mfp_m775_firmware" ||
    cpe == "cpe:/o:hp:laserjet_700_color_flow_mfp_m775_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000607")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000607 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064719")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064719 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_700_color_m712_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000605")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000605 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_flow_mfp_m830_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000617")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000617 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064718")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064718 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_m40[67]_firmware") {
  if (version_is_less(version: version, test_version: "2504171.023891")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023891 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_m4555_mfp_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000619")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000619 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_m506_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000588")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000588 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064715")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064715 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023895")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023895 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_m507_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064677")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064677 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023900")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023900 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_m604_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000616")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000616 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_m60[56]_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000616")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000616 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064715")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064715 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023908")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023908 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_m6(07|08|09|10|11|12)_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064682")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064682 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023871")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023871 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_m806_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000606")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000606 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064698")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064698 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_mfp_m43[01]_firmware") {
  if (version_is_less(version: version, test_version: "2504171.023906")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023906 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_m527_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_m527_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000587")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000587 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064715")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064715 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023870")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023870 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_m528_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064691")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064691 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023887")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023887 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_m630_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_m630_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000593")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000593 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064692")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064692 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_mfp_m63[1-6]_firmware" ||
    cpe =~ "^cpe:/o:hp:laserjet_flow_mfp_m63[1-6]_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064704")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064704 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023882")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023882 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_m725_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000609")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000609 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192_064688")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064688 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_500_color_mfp_m575_firmware" ||
    cpe == "cpe:/o:hp:laserjet_500_color_flow_mfp_m575_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000598")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000598 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064696")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064696 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}


if (cpe == "cpe:/o:hp:laserjet_500_color_mfp_m525_firmware" ||
    cpe == "cpe:/o:hp:laserjet_500_color_flow_mfp_m525_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000592")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000592 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064710")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064710 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_e40040_firmware") {
  if (version_is_less(version: version, test_version: "2504171.023891")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023891 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_e40045_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064715")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064715 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023895")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023895 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_e50145_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064677")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064677 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023900")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023900 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_e60[01][567]5_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064682")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064682 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023871")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023871 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_e52545_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e52545_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064715")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064715 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023870")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023870 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_e52645_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064691")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064691 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023887")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023887 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_mfp_e625[56]5_firmware" ||
    cpe =~ "^cpe:/o:hp:laserjet_flow_mfp_e625[567]5_firmware" ||
    cpe =~ "^cpe:/o:hp:laserjet_mfp_e626[56]5_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e62675_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064704")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064704 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023882")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023882 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_mfp_724(25|30)_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064699")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064699 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023883")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023883 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_mfp_e725(25|30|35)_firmware" ||
    cpe =~ "^cpe:/o:hp:laserjet_flow_mfp_e725(25|30|35)_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064694")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064694 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023894")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023894 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_mfp_e825[456]0" ||
    cpe =~ "^cpe:/o:hp:laserjet_flow_mfp_e825[456]0") {
  if (version_is_less(version: version, test_version: "2411192.064681")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064681 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023876")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023876 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_m527_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_m527_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000587")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000587 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064715")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064715 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023870")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023870 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:officejet_color_mfp_x585_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000591")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000591 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064705")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064705 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:officejet_color_x555_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000585")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000585 (3.9.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064716")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064716 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_755_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064713")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064713 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023890")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023890 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:pagewide_color_mfp_77[49]_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064700")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064700 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023886")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023886 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_556_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000603")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000603 (3.3.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064715")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064715 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023892")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023892 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_mfp_765_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064713")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064713 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023890")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023890 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_flow_mfp_785_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064708")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064708 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023879")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023879 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_mfp_586_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_flow_mfp_586_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000595")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000595 (3.3.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064715")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064715 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023874")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023874 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_mfp_780_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_flow_mfp_780_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064708")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064708 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023879")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023879 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_e55650_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000603")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000603 (3.3.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064715")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064715 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023892")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023892 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_e75160_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064713")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064713 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023890")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023890 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_mfp_e58650dn_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_flow_mfp_58650z_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000595")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000595 (3.3.9)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2400000", test_version_up: "2411192.064715")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064715 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023874")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023874 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_mfp_e77650_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_flow_mfp_e77660z_firmware" ||
    cpe =~ "^cpe:/o:hp:pagewide_color_flow_mfp_e776[56]0z_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064708")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064708 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023879")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023879 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_mfp_p77440_firmware" ||
    cpe =~ "^cpe:/o:hp:pagewide_color_mfp_p779[456]0_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064700")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064700 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023886")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023886 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_p75250_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064713")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064713 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023890")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023890 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:scanjet_enterprise_8500_fn1_firmware") {
  if (version_is_less(version: version, test_version: "2309059.000620")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2309059_000620 (3.3.9)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:scanjet_enterprise_flow_n9120_fn2_firmware") {
  if (version_is_less(version: version, test_version: "2411192.064683")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2411192_064683 (4.11.2.3)");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "2500000", test_version_up: "2504171.023895")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2504171_023895 (5.4)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_pro_552_firmware" ||
    cpe == "cpe:/o:hp:pagewide_p55250_firmware" ||
    cpe =~ "^cpe:/o:hp:pagewide_pro_452d[nw]_firmware" ||
    cpe == "cpe:/o:hp:pagewide_352dw_firmware" ||
    cpe =~ "^cpe:/o:hp:pagewide_pro_477d[nw]_firmware" ||
    cpe == "cpe:/o:hp:pagewide_pro_577dw_firmware" ||
    cpe == "cpe:/o:hp:pagewide_p57750dw_firmware" ||
    cpe == "cpe:/o:hp:pagewide_pro_577z_firmware" ||
    cpe == "cpe:/o:hp:pagewide_377dw_firmware") {
  # e.g. ICHDWOPP1N001.2142A.00
  version = substr(version, 14);
  if (version_is_less(version: version, test_version: "2208a")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "2208A");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:officejet_pro_821[06]_firmware") {
  # e.g. TESPDLPP1N001.1709A.00
  version = substr(version, 10);
  if (version_is_less(version: version, test_version: "001.2210b")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "001.2210B");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:officejet_pro_87[34]0_firmware") {
  # e.g. WEBPDLPP1N001.2211B.00
  version = substr(version, 10);
  if (version_is_less(version: version, test_version: "001.2207c")) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "001.2207C");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);
