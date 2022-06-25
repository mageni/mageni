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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2017.15");
  script_cve_id("CVE-2017-5470", "CVE-2017-5471", "CVE-2017-5472", "CVE-2017-7749", "CVE-2017-7750", "CVE-2017-7751", "CVE-2017-7752", "CVE-2017-7754", "CVE-2017-7755", "CVE-2017-7756", "CVE-2017-7757", "CVE-2017-7758", "CVE-2017-7759", "CVE-2017-7760", "CVE-2017-7761", "CVE-2017-7762", "CVE-2017-7763", "CVE-2017-7764", "CVE-2017-7765", "CVE-2017-7766", "CVE-2017-7767", "CVE-2017-7768", "CVE-2017-7770", "CVE-2017-7771", "CVE-2017-7772", "CVE-2017-7773", "CVE-2017-7774", "CVE-2017-7775", "CVE-2017-7776", "CVE-2017-7777", "CVE-2017-7778");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-03 12:16:00 +0000 (Fri, 03 Aug 2018)");

  script_name("Mozilla Firefox Security Advisory (MFSA2017-15) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2017-15");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-15/");
  script_xref(name:"URL", value:"http://www.unicode.org/reports/tr31/tr31-26.html#Aspirational_Use_Scripts");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1349604%2C1318645%2C1361098%2C1361100%2C1341026%2C1349421%2C1360852%2C1299147%2C1352073%2C1354853%2C1366446%2C1342181%2C1343069");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1359639%2C1349595%2C1352295%2C1352556%2C1342552%2C1342567%2C1346012%2C1366140%2C1368732%2C1297111%2C1362590%2C1357462%2C1363280%2C1349266%2C1352093%2C1348424%2C1347748%2C1356025%2C1325513%2C1367692");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1215648");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1273265");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1317242");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1336964");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1336979");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1342742");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1348645");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1349310");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1350047");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1352745");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1352747");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1355039");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1355174");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1355182");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1356558");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1356607");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1356824");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1356893");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1357090");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1358248");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1358551");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1359547");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1360309");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1361326");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1363396");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1364283");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1365602");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1366595");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1368490");
  script_xref(name:"URL", value:"https://sourceforge.net/p/nsis/bugs/1125/");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2017-5472: Use-after-free using destroyed node when regenerating trees
A use-after-free vulnerability with the frameloader during tree reconstruction while regenerating CSS layout when attempting to use a node in the tree that no longer exists. This results in a potentially exploitable crash.

CVE-2017-7749: Use-after-free during docshell reloading
A use-after-free vulnerability when using an incorrect URL during the reloading of a docshell. This results in a potentially exploitable crash.

CVE-2017-7750: Use-after-free with track elements
A use-after-free vulnerability during video control operations when a <track> element holds a reference to an older window if that window has been replaced in the DOM. This results in a potentially exploitable crash.

CVE-2017-7751: Use-after-free with content viewer listeners
A use-after-free vulnerability with content viewer listeners that results in a potentially exploitable crash.

CVE-2017-7752: Use-after-free with IME input
A use-after-free vulnerability during specific user interactions with the input method editor (IME) in some languages due to how events are handled. This results in a potentially exploitable crash but would require specific user interaction to trigger.

CVE-2017-7754: Out-of-bounds read in WebGL with ImageInfo object
An out-of-bounds read in WebGL with a maliciously crafted ImageInfo object during WebGL operations.

CVE-2017-7755: Privilege escalation through Firefox Installer with same directory DLL files
The Firefox installer on Windows can be made to load malicious DLL files stored in the same directory as the installer when it is run. This allows privileged execution if the installer is run with elevated privileges. Note: This attack only affects Windows operating systems. Other operating systems are unaffected.

CVE-2017-7756: Use-after-free and use-after-scope logging XHR header errors
A use-after-free and use-after-scope vulnerability when logging errors from headers for XML HTTP Requests (XHR). This could result in a potentially exploitable crash.

CVE-2017-7757: Use-after-free in IndexedDB
A use-after-free vulnerability in IndexedDB when one of its objects is destroyed in memory while a method on it is still being executed. This results in a potentially exploitable crash.

CVE-2017-7778: Vulnerabilities in the Graphite 2 library
A number of security vulnerabilities in the Graphite 2 library including out-of-bounds reads, buffer overflow reads and writes, and the use of uninitialized memory. These issues were addressed in Graphite 2 version 1.3.10.

CVE-2017-7758: Out-of-bounds read in Opus encoder
An out-of-bounds read vulnerability with the Opus encoder when the number of channels in an audio stream changes while the encoder is in use.

CVE-2017-7759: Android intent URLs can cause navigation to local file system
Android intent URLs given to Firefox for Android can be used to navigate from HTTP or ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 54.");

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

if (version_is_less(version: version, test_version: "54")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "54", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
