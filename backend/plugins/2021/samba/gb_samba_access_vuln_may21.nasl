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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145916");
  script_version("2021-05-06T08:53:12+0000");
  script_tag(name:"last_modification", value:"2021-05-06 08:53:12 +0000 (Thu, 06 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-06 08:45:40 +0000 (Thu, 06 May 2021)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:N");

  script_cve_id("CVE-2021-20254");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Samba 3.6.0 < 4.12.15, 4.13.0 < 4.13.8, 4.14.0 < 4.14.4 File Access Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"summary", value:"Samba is prone to a unauthorized file access vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Samba smbd file server must map Windows group identities
  (SIDs) into unix group ids (gids). The code that performs this had a flaw that could allow it
  to read data beyond the end of the array in the case where a negative cache entry had been added
  to the mapping cache. This could cause the calling code to return those values into the process
  token that stores the group membership for a user.

  Most commonly this flaw causes the calling code to crash, but it was found that an unprivileged
  user may be able to delete a file within a network share that they should have been disallowed
  access to.");

  script_tag(name:"affected", value:"Samba version 3.6.0 and later.");

  script_tag(name:"solution", value:"Update to version 4.12.15, 4.13.8, 4.14.4 or later.");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2021-20254.html");

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

if (version_in_range(version: version, test_version: "3.6", test_version2: "4.12.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.12.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version_in_range(version: version, test_version: "4.13.0", test_version2: "4.13.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.13.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version_in_range(version: version, test_version: "4.14.0", test_version2: "4.14.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.14.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
