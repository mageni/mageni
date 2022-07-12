# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = 'cpe:/a:cyrus:imap';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143263");
  script_version("2019-12-18T03:58:12+0000");
  script_tag(name:"last_modification", value:"2019-12-18 03:58:12 +0000 (Wed, 18 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-18 03:51:27 +0000 (Wed, 18 Dec 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2019-19783");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cyrus IMAP 2.5.x < 2.5.15, 3.0.x < 3.0.13 ACL Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_cyrus_imap_server_detect.nasl");
  script_mandatory_keys("cyrus/imap_server/detected");

  script_tag(name:"summary", value:"Cyrus IMAP is prone to an ACL bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If sieve script uploading is allowed (3.x) or certain non-default sieve
  options are enabled (2.x), a user with a mail account on the service can use a sieve script containing a
  fileinto directive to create any mailbox with administrator privileges, because of folder mishandling in
  autosieve_createfolder() in imap/lmtp_sieve.c.");

  script_tag(name:"affected", value:"Cyrus IMAP versions 2.5.0 - 2.5.14 and 3.0.0 - 3.0.12.");

  script_tag(name:"solution", value:"Update to version 2.5.15, 3.0.13 or later.");

  script_xref(name:"URL", value:"https://www.cyrusimap.org/imap/download/release-notes/2.5/x/2.5.15.html");
  script_xref(name:"URL", value:"https://www.cyrusimap.org/imap/download/release-notes/3.0/x/3.0.13.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "2.5", test_version2: "2.5.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.15");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.0", test_version2: "3.0.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.13");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
