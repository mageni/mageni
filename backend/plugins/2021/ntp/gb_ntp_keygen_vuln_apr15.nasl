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

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146236");
  script_version("2021-07-07T10:35:38+0000");
  script_tag(name:"last_modification", value:"2021-07-07 10:35:38 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-07 08:38:10 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2015-3405");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NTP < 4.2.8p2, 4.3.x < 4.3.12 Keygen Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_tag(name:"summary", value:"NTP is prone to a vulnerability in ntp-keygen.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ntp-keygen does not generate MD5 keys with sufficient entropy
  on big endian machines when the lowest order byte of the temp variable is between 0x20 and 0x7f
  and not #, which might allow remote attackers to obtain the value of generated MD5 keys via a
  brute force attack with the 93 possible keys.");

  script_tag(name:"affected", value:"NTPd versions prior to 4.2.8p2 and 4.3.x before 4.3.12.");

  script_tag(name:"solution", value:"Update to version 4.2.8p2 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2015/04/23/14");
  script_xref(name:"URL", value:"https://bugs.ntp.org/show_bug.cgi?id=2797");

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

if (version_is_less(version: version, test_version: "4.2.8p2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.8p2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^4\.3\." && version_is_less(version: version, test_version: "4.3.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);