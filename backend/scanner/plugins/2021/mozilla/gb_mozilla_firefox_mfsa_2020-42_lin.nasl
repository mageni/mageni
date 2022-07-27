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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2020.42");
  script_cve_id("CVE-2020-15673", "CVE-2020-15674", "CVE-2020-15675", "CVE-2020-15676", "CVE-2020-15677", "CVE-2020-15678");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 20:15:00 +0000 (Mon, 02 Nov 2020)");

  script_name("Mozilla Firefox Security Advisory (MFSA2020-42) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2020-42");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-42/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1648493%2C1660800");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1656063%2C1656064%2C1656067%2C1660293");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1641487");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1646140");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1654211");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1660211");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2020-15675: Use-After-Free in WebGL
When processing surfaces, the lifetime may outlive a persistent buffer leading to memory corruption and a potentially exploitable crash.

CVE-2020-15677: Download origin spoofing via redirect
By exploiting an Open Redirect vulnerability on a website, an attacker could have spoofed the site displayed in the download file dialog to show the original site (the one suffering from the open redirect) rather than the site the file was actually downloaded from.

CVE-2020-15676: XSS when pasting attacker-controlled data into a contenteditable element
Firefox sometimes ran the onload handler for SVG elements that the DOM sanitizer decided to remove, resulting in JavaScript being executed after pasting attacker-controlled data into a contenteditable element.

CVE-2020-15678: When recursing through layers while scrolling, an iterator may have become invalid, resulting in a potential use-after-free scenario
When recursing through graphical layers while scrolling, an iterator may have become invalid, resulting in a potential use-after-free. This occurs because the function APZCTreeManager::ComputeClippedCompositionBounds did not follow iterator invalidation rules.

CVE-2020-15673: Memory safety bugs fixed in Firefox 81 and Firefox ESR 78.3
Mozilla developer Jason Kratzer reported memory safety bugs present in Firefox 80 and Firefox ESR 78.2. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2020-15674: Memory safety bugs fixed in Firefox 81
Mozilla developers Byron Campen and Christian Holler reported memory safety bugs present in Firefox 80. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 81.");

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

if (version_is_less(version: version, test_version: "81")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "81", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
