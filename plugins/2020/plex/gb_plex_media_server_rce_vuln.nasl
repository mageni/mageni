# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143319");
  script_version("2020-01-07T07:49:39+0000");
  script_tag(name:"last_modification", value:"2020-01-07 07:49:39 +0000 (Tue, 07 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-07 07:35:17 +0000 (Tue, 07 Jan 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2019-19141");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Plex Media Server < 1.18.2.2041 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_plex_media_server_remote_detect.nasl");
  script_mandatory_keys("plex_media_server/detected");

  script_tag(name:"summary", value:"Plex Media Server is prone to an authenticated remote code execution
  vulnerability in the Camera Upload feature.");

  script_tag(name:"insight", value:"The Camera Upload functionality in Plex Media Server allows remote
  authenticated users to write files anywhere the user account running the Plex Media Server has permissions. This
  allows remote code execution via a variety of methods, such as (on a default Ubuntu installation) creating a
  .ssh folder in the plex user's home directory via directory traversal, uploading an SSH authorized_keys file
  there, and logging into the host as the Plex user via SSH.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Plex Media Server prior to version 1.18.2.2041.");

  script_tag(name:"solution", value:"Update to version 1.18.2.2041 or later.");

  script_xref(name:"URL", value:"https://forums.plex.tv/t/security-camera-upload/507289");

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

if (version_is_less(version: version, test_version: "1.18.2.2041")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.18.2.2041", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
