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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2018.15");
  script_cve_id("CVE-2018-12358", "CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12361", "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-12367", "CVE-2018-12368", "CVE-2018-12369", "CVE-2018-12370", "CVE-2018-12371", "CVE-2018-5156", "CVE-2018-5186", "CVE-2018-5187", "CVE-2018-5188");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-15T09:13:07+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Mozilla Firefox Security Advisory (MFSA2018-15) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2018-15");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-15/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1456189%2C1456975%2C1465898%2C1392739%2C1451297%2C1464063%2C1437842%2C1442722%2C1452576%2C1450688%2C1458264%2C1458270%2C1465108%2C1464829%2C1464079%2C1463494%2C1458048");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1461324%2C1414829%2C1395246%2C1467938%2C1461619%2C1425930%2C1438556%2C1454285%2C1459568%2C1463884");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1464872%2C1463329%2C1419373%2C1412882%2C1413033%2C1444673%2C1454448%2C1453505%2C1438671");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1436241");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1452375");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1453127");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1454909");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1456652");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1459162");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1459206");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1459693");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1462891");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1463244");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1464039");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1464784");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1465686");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1467852");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1468217");
  script_xref(name:"URL", value:"https://posts.specterops.io/the-tale-of-settingcontent-ms-files-f1ea253e4d39");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2018-12359: Buffer overflow using computed size of canvas element
A buffer overflow can occur when rendering canvas content while adjusting the height and width of the <canvas> element dynamically, causing data to be written outside of the currently computed boundaries. This results in a potentially exploitable crash.

CVE-2018-12360: Use-after-free when using focus()
A use-after-free vulnerability can occur when deleting an input element during a mutation event handler triggered by focusing that element. This results in a potentially exploitable crash.

CVE-2018-12361: Integer overflow in SwizzleData
An integer overflow can occur in the SwizzleData code while calculating buffer sizes. The overflowed value is used for subsequent graphics computations when their inputs are not sanitized which results in a potentially exploitable crash.

CVE-2018-12358: Same-origin bypass using service worker and redirection
Service workers can use redirection to avoid the tainting of cross-origin resources in some instances, allowing a malicious site to read responses which are supposed to be opaque.

CVE-2018-12362: Integer overflow in SSSE3 scaler
An integer overflow can occur during graphics operations done by the Supplemental Streaming SIMD Extensions 3 (SSSE3) scaler, resulting in a potentially exploitable crash.

CVE-2018-5156: Media recorder segmentation fault when track type is changed during capture
A vulnerability can occur when capturing a media stream when the media source type is changed as the capture is occurring. This can result in stream data being cast to the wrong type causing a potentially exploitable crash.

CVE-2018-12363: Use-after-free when appending DOM nodes
A use-after-free vulnerability can occur when script uses mutation events to move DOM nodes between documents, resulting in the old document that held the node being freed but the node still having a pointer referencing it. This results in a potentially exploitable crash.

CVE-2018-12364: CSRF attacks through 307 redirects and NPAPI plugins
NPAPI plugins, such as Adobe Flash, can send non-simple cross-origin requests, bypassing CORS by making a same-origin POST that does a 307 redirect to the target site. This allows for a malicious site to engage in cross-site request forgery (CSRF) attacks.

CVE-2018-12365: Compromised IPC child process can list local filenames
A compromised IPC child process can escape the content sandbox and list the names of arbitrary files on the file system without user consent or interaction. This could result in exposure of private local files.

CVE-2018-12371: Integer overflow in Skia library during edge builder allocation
An integer overflow vulnerability in the Skia library when allocating memory for edge builders on some systems with at least 16 GB of RAM. This results in the use of uninitialized memory, resulting in a potentially exploitable crash.

CVE-2018-12366: Invalid ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 61.");

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

if (version_is_less(version: version, test_version: "61")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "61", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
