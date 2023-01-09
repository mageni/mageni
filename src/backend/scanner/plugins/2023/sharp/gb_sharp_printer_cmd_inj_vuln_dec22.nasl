# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.149051");
  script_version("2023-01-02T12:25:43+0000");
  script_tag(name:"last_modification", value:"2023-01-02 12:25:43 +0000 (Mon, 02 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-02 08:00:19 +0000 (Mon, 02 Jan 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2022-45796");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SHARP Printer Command Injection Vulnerability (Dec 2022)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_xerox_printer_consolidation.nasl");
  script_mandatory_keys("xerox/printer/detected");

  script_tag(name:"summary", value:"Multiple SHARP printers are prone to a command injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the
  target host.");

  script_tag(name:"insight", value:"Command injection security vulnerability was identified and may
  impact some MFPs that are not properly protected with a strong admin password and firewall.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://global.sharp/products/copier/info/info_security_2022-11.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:sharp:bp-70c65_firmware",
                     "cpe:/o:sharp:bp-70c55_firmware",
                     "cpe:/o:sharp:bp-70c45_firmware",
                     "cpe:/o:sharp:bp-70c36_firmware",
                     "cpe:/o:sharp:bp-70c31_firmware",
                     "cpe:/o:sharp:bp-60c45_firmware",
                     "cpe:/o:sharp:bp-60c36_firmware",
                     "cpe:/o:sharp:bp-60c31_firmware",
                     "cpe:/o:sharp:bp-50c65_firmware",
                     "cpe:/o:sharp:bp-50c55_firmware",
                     "cpe:/o:sharp:bp-50c45_firmware",
                     "cpe:/o:sharp:bp-50c36_firmware",
                     "cpe:/o:sharp:bp-50c31_firmware",
                     "cpe:/o:sharp:bp-50c26_firmware",
                     "cpe:/o:sharp:bp-55c26_firmware",
                     "cpe:/o:sharp:mx-8081_firmware",
                     "cpe:/o:sharp:mx-7081_firmware",
                     "cpe:/o:sharp:mx-6071_firmware",
                     "cpe:/o:sharp:mx-5071_firmware",
                     "cpe:/o:sharp:mx-4071_firmware",
                     "cpe:/o:sharp:mx-3571_firmware",
                     "cpe:/o:sharp:mx-3071_firmware",
                     "cpe:/o:sharp:mx-4061_firmware",
                     "cpe:/o:sharp:mx-3561_firmware",
                     "cpe:/o:sharp:mx-3061_firmware",
                     "cpe:/o:sharp:mx-6051_firmware",
                     "cpe:/o:sharp:mx-5051_firmware",
                     "cpe:/o:sharp:mx-4051_firmware",
                     "cpe:/o:sharp:mx-3551_firmware",
                     "cpe:/o:sharp:mx-3051_firmware",
                     "cpe:/o:sharp:mx-2651_firmware",
                     "cpe:/o:sharp:mx-6071s_firmware",
                     "cpe:/o:sharp:mx-5071s_firmware",
                     "cpe:/o:sharp:mx-4071s_firmware",
                     "cpe:/o:sharp:mx-3571s_firmware",
                     "cpe:/o:sharp:mx-3071s_firmware",
                     "cpe:/o:sharp:mx-4061s_firmware",
                     "cpe:/o:sharp:mx-3561s_firmware",
                     "cpe:/o:sharp:mx-3061s_firmware",
                     "cpe:/o:sharp:bp-30c25_firmware",
                     "cpe:/o:sharp:bp-30c25y_firmware",
                     "cpe:/o:sharp:bp-30c25z_firmware",
                     "cpe:/o:sharp:bp-30c25t_firmware",
                     "cpe:/o:sharp:mx-7580n_firmware",
                     "cpe:/o:sharp:mx-6580n_firmware",
                     "cpe:/o:sharp:mx-8090n_firmware",
                     "cpe:/o:sharp:mx-7090n_firmware",
                     "cpe:/o:sharp:mx-6070n_firmware",
                     "cpe:/o:sharp:mx-5070n_firmware",
                     "cpe:/o:sharp:mx-4070n_firmware",
                     "cpe:/o:sharp:mx-3570n_firmware",
                     "cpe:/o:sharp:mx-3070n_firmware",
                     "cpe:/o:sharp:mx-4060n_firmware",
                     "cpe:/o:sharp:mx-3560n_firmware",
                     "cpe:/o:sharp:mx-3060n_firmware",
                     "cpe:/o:sharp:mx-6070v_firmware",
                     "cpe:/o:sharp:mx-5070v_firmware",
                     "cpe:/o:sharp:mx-4070v_firmware",
                     "cpe:/o:sharp:mx-3570v_firmware",
                     "cpe:/o:sharp:mx-3070v_firmware",
                     "cpe:/o:sharp:mx-4060v_firmware",
                     "cpe:/o:sharp:mx-3560v_firmware",
                     "cpe:/o:sharp:mx-6050n_firmware",
                     "cpe:/o:sharp:mx-5050n_firmware",
                     "cpe:/o:sharp:mx-4050n_firmware",
                     "cpe:/o:sharp:mx-3550n_firmware",
                     "cpe:/o:sharp:mx-3050n_firmware",
                     "cpe:/o:sharp:mx-6050v_firmware",
                     "cpe:/o:sharp:mx-5050v_firmware",
                     "cpe:/o:sharp:mx-4050v_firmware",
                     "cpe:/o:sharp:mx-3550v_firmware",
                     "cpe:/o:sharp:mx-3050v_firmware",
                     "cpe:/o:sharp:mx-2630n_firmware",
                     "cpe:/o:sharp:mx-c304w_firmware",
                     "cpe:/o:sharp:mx-c303w_firmware",
                     "cpe:/o:sharp:mx-c304_firmware",
                     "cpe:/o:sharp:mx-c303_firmware",
                     "cpe:/o:sharp:mx-c304wh_firmware",
                     "cpe:/o:sharp:mx-c303wh_firmware",
                     "cpe:/o:sharp:bp-70m90_firmware",
                     "cpe:/o:sharp:bp-70m75_firmware",
                     "cpe:/o:sharp:bp-70m65_firmware",
                     "cpe:/o:sharp:bp-70m55_firmware",
                     "cpe:/o:sharp:bp-70m45_firmware",
                     "cpe:/o:sharp:bp-70m36_firmware",
                     "cpe:/o:sharp:bp-70m31_firmware",
                     "cpe:/o:sharp:bp-50m55_firmware",
                     "cpe:/o:sharp:bp-50m50_firmware",
                     "cpe:/o:sharp:bp-50m45_firmware",
                     "cpe:/o:sharp:bp-50m36_firmware",
                     "cpe:/o:sharp:bp-50m31_firmware",
                     "cpe:/o:sharp:bp-50m26_firmware",
                     "cpe:/o:sharp:mx-m1206_firmware",
                     "cpe:/o:sharp:mx-m1056_firmware",
                     "cpe:/o:sharp:mx-m7570_firmware",
                     "cpe:/o:sharp:mx-m6570_firmware",
                     "cpe:/o:sharp:mx-m6071_firmware",
                     "cpe:/o:sharp:mx-m5071_firmware",
                     "cpe:/o:sharp:mx-m4071_firmware",
                     "cpe:/o:sharp:mx-m3571_firmware",
                     "cpe:/o:sharp:mx-m3071_firmware",
                     "cpe:/o:sharp:mx-m6051_firmware",
                     "cpe:/o:sharp:mx-m5051_firmware",
                     "cpe:/o:sharp:mx-m4051_firmware",
                     "cpe:/o:sharp:mx-m3551_firmware",
                     "cpe:/o:sharp:mx-m3051_firmware",
                     "cpe:/o:sharp:mx-m2651_firmware",
                     "cpe:/o:sharp:mx-m3571s_firmware",
                     "cpe:/o:sharp:mx-m3071s_firmware",
                     "cpe:/o:sharp:mx-m6071s_firmware",
                     "cpe:/o:sharp:mx-m5071s_firmware",
                     "cpe:/o:sharp:mx-m4071s_firmware",
                     "cpe:/o:sharp:bp-30m35_firmware",
                     "cpe:/o:sharp:bp-30m31_firmware",
                     "cpe:/o:sharp:bp-30m28_firmware",
                     "cpe:/o:sharp:bp-30m35t_firmware",
                     "cpe:/o:sharp:bp-30m31t_firmware",
                     "cpe:/o:sharp:bp-30m28t_firmware",
                     "cpe:/o:sharp:mx-b476w_firmware",
                     "cpe:/o:sharp:mx-b376w_firmware",
                     "cpe:/o:sharp:mx-b456w_firmware",
                     "cpe:/o:sharp:mx-b356w_firmware",
                     "cpe:/o:sharp:mx-b476wh_firmware",
                     "cpe:/o:sharp:mx-b376wh_firmware",
                     "cpe:/o:sharp:mx-b456wh_firmware",
                     "cpe:/o:sharp:mx-b356wh_firmware",
                     "cpe:/o:sharp:mx-m905_firmware",
                     "cpe:/o:sharp:mx-m6070_firmware",
                     "cpe:/o:sharp:mx-m5070_firmware",
                     "cpe:/o:sharp:mx-m4070_firmware",
                     "cpe:/o:sharp:mx-m3570_firmware",
                     "cpe:/o:sharp:mx-m3070_firmware",
                     "cpe:/o:sharp:mx-m6050_firmware",
                     "cpe:/o:sharp:mx-m5050_firmware",
                     "cpe:/o:sharp:mx-m4050_firmware",
                     "cpe:/o:sharp:mx-m3550_firmware",
                     "cpe:/o:sharp:mx-m3050_firmware",
                     "cpe:/o:sharp:mx-m2630_firmware",
                     "cpe:/o:sharp:mx-b455w_firmware",
                     "cpe:/o:sharp:mx-b355w_firmware",
                     "cpe:/o:sharp:mx-b455wz_firmware",
                     "cpe:/o:sharp:mx-b355wz_firmware",
                     "cpe:/o:sharp:mx-b455wt_firmware",
                     "cpe:/o:sharp:mx-b355wt_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = infos["version"];
cpe = infos["cpe"];

check_vers = substr(version, 1, 4);

if (cpe =~ "^cpe:/o:sharp:bp\-(50|55|60|70)c") {
  if (version_is_less_equal(version: check_vers, test_version: "2.02")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:sharp:mx\-[78]081_firmware") {
  if (version_is_less_equal(version: check_vers, test_version: "1.20")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:sharp:mx\-(6071s?|5071s?|4071s?|3571s?|3071s?|4061s?|3561s?|3061s?|6051|5051|4051|3551|3051|2651)") {
  if (version_is_less_equal(version: check_vers, test_version: "6.00")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:sharp:bp\-30c25") {
  if (version_is_less_equal(version: check_vers, test_version: "1.21")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:sharp:mx\-[67]580n") {
  if (version_is_less_equal(version: check_vers, test_version: "5.00")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:sharp:mx\-[78]090n") {
  if (version_is_less_equal(version: check_vers, test_version: "4.02")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:sharp:mx\-(6070[nv]|5070[nv]|4070[nv]|3570[nv]|3070[nv]|4060[nv]|3560[nv]|3060[nv]|6050[nv]|5050[nv]|4050[nv]|3550[nv]|3050[nv]|2630n)") {
  if (version_is_less_equal(version: check_vers, test_version: "7.90")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:sharp:mx\-c30[34]") {
  if (version_is_less_equal(version: check_vers, test_version: "5.00")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:sharp:bp\-70m(75|90)") {
  if (version_is_less_equal(version: check_vers, test_version: "2.00")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:sharp:bp\-(50|70)m") {
  if (version_is_less_equal(version: check_vers, test_version: "2.11")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:sharp:mx\-m(1056|1206)") {
  if (version_is_less_equal(version: check_vers, test_version: "1.02")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:sharp:mx\-m[67]570") {
  if (version_is_less_equal(version: check_vers, test_version: "4.53")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:sharp:mx\-m(6071s?|5071s?|4071s?|3571s?|3071s?|6051|5051|4051|3551|3051|2651)") {
  if (version_is_less_equal(version: check_vers, test_version: "4.00")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:sharp:bp\-30m") {
  if (version_is_less_equal(version: check_vers, test_version: "2.02")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:sharp:mx\-b(476|376|456|356)") {
  if (version_is_less_equal(version: check_vers, test_version: "4.00")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:sharp:mx-m905_firmware") {
  if (version_is_less_equal(version: check_vers, test_version: "6.02")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:sharp:mx\-m(6070|5070|4070|3570|3070|6050|5050|4050|3550|3050|2630)") {
  if (version_is_less_equal(version: check_vers, test_version: "5.00")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:sharp:mx\-b[34]55w") {
  if (version_is_less_equal(version: check_vers, test_version: "4.01")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
