# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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

CPE = "cpe:/a:ui:unifi_video";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143681");
  script_version("2020-04-08T05:57:35+0000");
  script_tag(name:"last_modification", value:"2020-04-08 11:51:46 +0000 (Wed, 08 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-08 04:52:39 +0000 (Wed, 08 Apr 2020)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2020-8146");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("UniFi Video < 3.10.3 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ubnt_unifi_video_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ubnt/unifi_video/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"UniFi Video on Windows is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"UniFi contains a local privileges escalation to SYSTEM from arbitrary file
  deletetion and a DLL hijack vulnerability.");

  script_tag(name:"affected", value:"UniFi Video version 3.10.2 and prior on Windows.");

  script_tag(name:"solution", value:"Update to version 3.10.3 or later.");

  script_xref(name:"URL", value:"https://community.ui.com/releases/Security-advisory-bulletin-006-006/3cf6264e-e0e6-4e26-a331-1d271f84673e");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.10.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
