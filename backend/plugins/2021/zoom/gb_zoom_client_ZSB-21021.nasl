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

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147340");
  script_version("2021-12-16T05:43:26+0000");
  script_tag(name:"last_modification", value:"2021-12-16 11:53:28 +0000 (Thu, 16 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-16 05:34:43 +0000 (Thu, 16 Dec 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2021-34425");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zoom Client < 5.7.3 SSRF Vulnerability (ZSB-21021)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zoom_client_ssh_login_macosx_detect.nasl", "gb_zoom_client_smb_login_detect.nasl",
                      "gb_zoom_client_ssh_login_linux_detect.nasl");
  script_mandatory_keys("zoom/client/detected");

  script_tag(name:"summary", value:"Zoom Client is prone to a server-side request forgery (SSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Zoom Client for Meetings contains a SSRF vulnerability in
  the chat's 'link preview' functionality. If a user were to enable the chat's 'link preview'
  feature, a malicious actor could trick the user into potentially sending arbitrary HTTP GET
  requests to URLs that the actor cannot reach directly.");

  script_tag(name:"affected", value:"Zoom Client before version 5.7.3.");

  script_tag(name:"solution", value:"Update to version 5.7.3 or later.");

  script_xref(name:"URL", value:"https://explore.zoom.us/en/trust/security/security-bulletin/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.7.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.3", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
