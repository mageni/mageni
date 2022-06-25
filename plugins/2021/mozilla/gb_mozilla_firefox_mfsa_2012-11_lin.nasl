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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2012.11");
  script_cve_id("CVE-2011-3026");
  script_tag(name:"creation_date", value:"2021-11-16 11:08:07 +0000 (Tue, 16 Nov 2021)");
  script_version("2021-11-16T11:08:07+0000");
  script_tag(name:"last_modification", value:"2021-11-16 11:08:07 +0000 (Tue, 16 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mozilla Firefox Security Advisory (MFSA2012-11) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2012-11");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-11/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=727401");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libpng integer overflow
An integer overflow in the libpng library can lead to a heap-buffer
overflow when decompressing certain PNG images. This leads to a
crash, which may be potentially exploitable.");

  script_tag(name:"affected", value:"Firefox version(s) below 3.6.27 and below 10.0.2.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.6.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.27", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}
if (version_in_range_exclusive(version: version, test_version_lo: "4",  test_version_up: "10.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.2", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
