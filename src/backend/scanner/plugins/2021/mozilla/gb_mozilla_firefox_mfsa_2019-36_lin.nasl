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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2019.36");
  script_cve_id("CVE-2019-11745", "CVE-2019-11756", "CVE-2019-13722", "CVE-2019-17005", "CVE-2019-17008", "CVE-2019-17009", "CVE-2019-17010", "CVE-2019-17011", "CVE-2019-17012", "CVE-2019-17013", "CVE-2019-17014");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-19 16:22:00 +0000 (Fri, 19 Feb 2021)");

  script_name("Mozilla Firefox Security Advisory (MFSA2019-36) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2019-36");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-36/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1298509%2C1472328%2C1577439%2C1577937%2C1580320%2C1584195%2C1585106%2C1586293%2C1593865%2C1594181");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1449736%2C1533957%2C1560667%2C1567209%2C1580288%2C1585760%2C1592502");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1322864");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1508776");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1510494");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1546331");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1580156");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1581084");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1584170");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1586176");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1591334");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2019-11756: Use-after-free of SFTKSession object
Improper refcounting of soft token session objects could cause a use-after-free and crash (likely limited to a denial of service).

CVE-2019-17008: Use-after-free in worker destruction
When using nested workers, a use-after-free could occur during worker destruction. This resulted in a potentially exploitable crash.

CVE-2019-13722: Stack corruption due to incorrect number of arguments in WebRTC code
When setting a thread name on Windows in WebRTC, an incorrect number of arguments could have been supplied, leading to stack corruption and a potentially exploitable crash. Note: this issue only occurs on Windows. Other operating systems are unaffected.

CVE-2019-11745: Out of bounds write in NSS when encrypting with a block cipher
When encrypting with a block cipher, if a call to NSC_EncryptUpdate was made with data smaller than the block size, a small out of bounds write could occur. This could have caused heap corruption and a potentially exploitable crash.

CVE-2019-17014: Dragging and dropping a cross-origin resource, incorrectly loaded as an image, could result in information disclosure
If an image had not loaded correctly (such as when it is not actually an image), it could be dragged and dropped cross-domain, resulting in a cross-origin information leak.

CVE-2019-17009: Updater temporary files accessible to unprivileged processes
When running, the updater service wrote status and log files to an unrestricted location, potentially allowing an unprivileged process to locate and exploit a vulnerability in file handling in the updater service. Note: This attack requires local system access and only affects Windows. Other operating systems are not affected.

CVE-2019-17010: Use-after-free when performing device orientation checks
Under certain conditions, when checking the Resist Fingerprinting preference during device orientation checks, a race condition could have caused a use-after-free and a potentially exploitable crash.

CVE-2019-17005: Buffer overflow in plain text serializer
The plain text serializer used a fixed-size array for the number of elements it could process, however it was possible to overflow the static-sized array leading to memory corruption and a potentially exploitable crash.

CVE-2019-17011: Use-after-free when retrieving a document in antitracking
Under certain conditions, when retrieving a document from a DocShell in the antitracking code, a race condition could cause a use-after-free condition and a potentially exploitable crash.

CVE-2019-17012: Memory safety bugs fixed in Firefox 71 and Firefox ESR 68.3
Mozilla developers Christoph Diehl, Nathan Froyd, Jason Kratzer, Christian Holler, Karl Tomlinson, Tyson Smith reported memory safety bugs present in Firefox 70 and Firefox ESR 68.2. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 71.");

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

if (version_is_less(version: version, test_version: "71")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "71", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
