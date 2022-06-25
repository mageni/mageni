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

CPE = "cpe:/a:cyrus:imap";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146616");
  script_version("2021-09-02T11:45:41+0000");
  script_tag(name:"last_modification", value:"2021-09-03 12:13:43 +0000 (Fri, 03 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-02 11:38:55 +0000 (Thu, 02 Sep 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2021-33582");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cyrus IMAP < 3.0.16, 3.2.x < 3.2.8, 3.4.x < 3.4.2 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_cyrus_imap_server_detect.nasl");
  script_mandatory_keys("cyrus/imap_server/detected");

  script_tag(name:"summary", value:"Cyrus IMAP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Certain user inputs are used as hash table keys during
  processing. A poorly chosen string hashing algorithm meant that the user could control which
  bucket their data was stored in, allowing a malicious user to direct many inputs to a single
  bucket. Each subsequent insertion to the same bucket requires a strcmp of every other entry in
  it. At tens of thousands of entries, each new insertion could keep the CPU busy in a strcmp loop
  for minutes.");

  script_tag(name:"affected", value:"Cyrus IMAP prior to version 3.0.16, version 3.2.x through
  3.2.7 and 3.4.x through 3.4.1.");

  script_tag(name:"solution", value:"Update to version 3.0.16, 3.2.8, 3.4.2 or later.");

  script_xref(name:"URL", value:"https://cyrus.topicbox.com/groups/announce/T3dde0a2352462975-M1386fc44adf967e072f8df13");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "3.0.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.16");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.2.0", test_version2: "3.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.8");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.4.0", test_version2: "3.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
