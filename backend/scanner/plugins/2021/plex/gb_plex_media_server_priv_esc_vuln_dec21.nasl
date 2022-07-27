# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.147288");
  script_version("2021-12-09T06:38:16+0000");
  script_tag(name:"last_modification", value:"2021-12-09 11:40:32 +0000 (Thu, 09 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-09 06:33:47 +0000 (Thu, 09 Dec 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2021-42835");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Plex Media Server < 1.25.0 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_plex_media_server_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("plex_media_server/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Plex Media Server is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker (with a foothold in a endpoint via a low-privileged
  user account) can access the exposed RPC service of the update service component. This RPC
  functionality allows the attacker to interact with the RPC functionality and execute code from a
  path of his choice (local, or remote via SMB) because of a TOCTOU race condition. This code
  execution is in the context of the Plex update service (which runs as SYSTEM).");

  script_tag(name:"affected", value:"Plex Media Server prior to version 1.25.0.5282 on Windows.");

  script_tag(name:"solution", value:"Update to version 1.25.0.5282 or later.");

  script_xref(name:"URL", value:"https://forums.plex.tv/t/security-regarding-cve-2021-42835/761510");
  script_xref(name:"URL", value:"https://ir-on.io/2021/12/02/local-privilege-plexcalation/");

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

if (version_is_less(version: version, test_version: "1.25.0.5282")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.25.0.5282", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
