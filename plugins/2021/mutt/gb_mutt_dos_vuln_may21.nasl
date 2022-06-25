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

CPE = "cpe:/a:mutt:mutt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145930");
  script_version("2021-05-11T02:09:45+0000");
  script_tag(name:"last_modification", value:"2021-05-11 12:03:50 +0000 (Tue, 11 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-11 02:04:32 +0000 (Tue, 11 May 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2021-32055");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mutt 1.11.0 < 2.0.7 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_mutt_detect.nasl");
  script_mandatory_keys("mutt/detected");

  script_tag(name:"summary", value:"Mutt is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Mutt has a $imap_qresync issue in which imap/util.c has an
  out-of-bounds read in situations where an IMAP sequence set ends with a comma.

  NOTE: the $imap_qresync setting for QRESYNC is not enabled by default.");

  script_tag(name:"affected", value:"Mutt version 1.11.0 through 2.0.6.");

  script_tag(name:"solution", value:"Update to version 2.0.7 or later.");

  script_xref(name:"URL", value:"http://lists.mutt.org/pipermail/mutt-announce/Week-of-Mon-20210503/000036.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "1.11.0", test_version2: "2.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.7", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
