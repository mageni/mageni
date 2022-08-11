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
  script_oid("1.3.6.1.4.1.25623.1.0.145932");
  script_version("2021-05-11T03:30:10+0000");
  script_tag(name:"last_modification", value:"2021-05-11 12:03:50 +0000 (Tue, 11 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-11 03:04:19 +0000 (Tue, 11 May 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2021-32056");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cyrus IMAP < 3.2.7, 3.3.x < 3.4.1 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_cyrus_imap_server_detect.nasl");
  script_mandatory_keys("cyrus/imap_server/detected");

  script_tag(name:"summary", value:"Cyrus IMAP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Remote authenticated users could bypass intended access restrictions
  on certain server annotations. Additionally, a long-standing bug in replication did not allow
  server annotations to be replicated. Combining these two bugs, a remote authenticated user could
  stall replication, requiring administrator intervention.");

  script_tag(name:"affected", value:"Cyrus IMAP prior to version 3.2.7 and version 3.3.x through 3.4.0.");

  script_tag(name:"solution", value:"Update to version 3.2.7, 3.4.1 or later.");

  script_xref(name:"URL", value:"https://www.cyrusimap.org/imap/download/release-notes/3.2/x/3.2.7.html");
  script_xref(name:"URL", value:"https://www.cyrusimap.org/imap/download/release-notes/3.4/x/3.4.1.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "3.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.7");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.3.0", test_version2: "3.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
