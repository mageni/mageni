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

CPE = "cpe:/a:ui:unifi_protect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145460");
  script_version("2021-02-26T03:39:32+0000");
  script_tag(name:"last_modification", value:"2021-02-26 11:25:03 +0000 (Fri, 26 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-26 03:35:34 +0000 (Fri, 26 Feb 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2021-22882");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("UniFi Protect <= 1.13.7 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ui_unifi_protect_ubnt_detect.nasl");
  script_mandatory_keys("ui/unifi_protect/detected");

  script_tag(name:"summary", value:"UniFi Protect is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in UniFi Protect that would allow an attacker to
  use spoofed cameras to perform a DoS attack that could cause the UniFi Protect controller to crash.");

  script_tag(name:"affected", value:"UniFi Protect version 1.13.7 and prior.");

  script_tag(name:"solution", value:"Update to version 1.17.1 or later.");

  script_xref(name:"URL", value:"https://community.ui.com/releases/Security-advisory-bulletin-017-017/071141e5-bc2e-4b71-81f3-5e499316fcee");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.13.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.17.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
