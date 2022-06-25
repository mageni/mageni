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

CPE = "cpe:/a:plex:plex_media_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143755");
  script_version("2020-04-23T07:03:26+0000");
  script_tag(name:"last_modification", value:"2020-04-23 10:03:00 +0000 (Thu, 23 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-23 06:59:10 +0000 (Thu, 23 Apr 2020)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2020-5740");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Plex Media Server < 1.19.2.2673 Local Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_plex_media_server_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("plex_media_server/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Plex Media Server is prone to an local unauthenticated code execution vulnerability.");

  script_tag(name:"insight", value:"Improper Input Validation in Plex Media Server on Windows allows a local,
  unauthenticated attacker to execute arbitrary Python code with SYSTEM privileges.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Plex Media Server prior to version 1.19.2.2673 on Windows.");

  script_tag(name:"solution", value:"Update to version 1.19.2.2673 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/research/tra-2020-25");

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

if (version_is_less(version: version, test_version: "1.19.2.2673")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.19.2.2673", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
