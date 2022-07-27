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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2012.44");
  script_cve_id("CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954");
  script_tag(name:"creation_date", value:"2021-11-11 09:42:47 +0000 (Thu, 11 Nov 2021)");
  script_version("2021-11-15T10:21:31+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mozilla Firefox Security Advisory (MFSA2012-44) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2012-44");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-44/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=752902");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=759249");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=765139");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=765218");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gecko memory corruption
Google security researcher Abhishek Arya used the Address
Sanitizer tool to uncover four issues: two use-after-free problems, one out of
bounds read bug, and a bad cast. The first use-after-free problem is caused
when an array of nsSMILTimeValueSpec objects is destroyed but attempts are made
to call into objects in this array later. The second use-after-free problem is
in nsDocument::AdoptNode when it adopts into an empty document and then adopts
into another document, emptying the first one. The heap buffer overflow is in
ElementAnimations when data is read off of end of an array and then pointers are
dereferenced. The bad cast happens when nsTableFrame::InsertFrames is called
with frames in aFrameList that are a mix of row group frames and column group
frames. AppendFrames is not able to handle this mix.");

  script_tag(name:"affected", value:"Firefox version(s) below 14.");

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

if (version_is_less(version: version, test_version: "14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
