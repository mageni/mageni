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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2018.02");
  script_cve_id("CVE-2018-5089", "CVE-2018-5090", "CVE-2018-5091", "CVE-2018-5092", "CVE-2018-5093", "CVE-2018-5094", "CVE-2018-5095", "CVE-2018-5097", "CVE-2018-5098", "CVE-2018-5099", "CVE-2018-5100", "CVE-2018-5101", "CVE-2018-5102", "CVE-2018-5103", "CVE-2018-5104", "CVE-2018-5105", "CVE-2018-5106", "CVE-2018-5107", "CVE-2018-5108", "CVE-2018-5109", "CVE-2018-5110", "CVE-2018-5111", "CVE-2018-5112", "CVE-2018-5113", "CVE-2018-5114", "CVE-2018-5115", "CVE-2018-5116", "CVE-2018-5117", "CVE-2018-5118", "CVE-2018-5119", "CVE-2018-5121", "CVE-2018-5122");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-03 14:53:00 +0000 (Fri, 03 Aug 2018)");

  script_name("Mozilla Firefox Security Advisory (MFSA2018-02) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2018-02");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-02/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1412420%2C1426783%2C1422389%2C1415598%2C1410134%2C1408017%2C1224396%2C1382366%2C1415582%2C1417797%2C1409951%2C1414452%2C1428589%2C1425780%2C1399520%2C1418854%2C1408276%2C1412145%2C1331209%2C1425612");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1413857%2C1412653%2C1418966%2C1427126%2C1412942%2C1401459%2C1364399%2C1382851%2C1423770%2C1401420%2C1281965%2C1389561%2C1409179%2C1416879%2C1421786%2C1426449%2C1416799%2C1400912%2C1415158%2C1415748%2C1415788%2C1371891%2C1415770%2C1416519%2C1413143%2C1418841%2C1384544%2C1410140%2C1411631%2C1412313%2C1412641%2C1412645%2C1412646%2C1412648%2C1261175");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1321619");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1379276");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1387427");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1390882");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1395508");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1396399");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1399400");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1402368");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1405599");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1408708");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1409449");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1413841");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1415291");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1415883");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1416878");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1417405");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1417661");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1418074");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1418447");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1419363");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1420049");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1420507");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1421099");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1421324");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1423086");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1423159");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1423275");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1425000");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1425224");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1425267");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2018-5091: Use-after-free with DTMF timers
A use-after-free vulnerability can occur during WebRTC connections when interacting with the DTMF timers. This results in a potentially exploitable crash.

CVE-2018-5092: Use-after-free in Web Workers
A use-after-free vulnerability can occur when the thread for a Web Worker is freed from memory prematurely instead of from memory in the main thread while cancelling fetch operations.

CVE-2018-5093: Buffer overflow in WebAssembly during Memory/Table resizing
A heap buffer overflow vulnerability may occur in WebAssembly during Memory/Table resizing, resulting in a potentially exploitable crash.

CVE-2018-5094: Buffer overflow in WebAssembly with garbage collection on uninitialized memory
A heap buffer overflow vulnerability may occur in WebAssembly when shrinkElements is called followed by garbage collection on memory that is now uninitialized. This results in a potentially exploitable crash.

CVE-2018-5095: Integer overflow in Skia library during edge builder allocation
An integer overflow vulnerability in the Skia library when allocating memory for edge builders on some systems with at least 8 GB of RAM. This results in the use of uninitialized memory, resulting in a potentially exploitable crash.

CVE-2018-5097: Use-after-free when source document is manipulated during XSLT
A use-after-free vulnerability can occur during XSL transformations when the source document for the transformation is manipulated by script content during the transformation. This results in a potentially exploitable crash.

CVE-2018-5098: Use-after-free while manipulating form input elements
A use-after-free vulnerability can occur when form input elements, focus, and selections are manipulated by script content. This results in a potentially exploitable crash.

CVE-2018-5099: Use-after-free with widget listener
A use-after-free vulnerability can occur when the widget listener is holding strong references to browser objects that have previously been freed, resulting in a potentially exploitable crash when these references are used.

CVE-2018-5100: Use-after-free when IsPotentiallyScrollable arguments are freed from memory
A use-after-free vulnerability can occur when arguments passed to the IsPotentiallyScrollable function are freed while still in use by scripts. This results in a potentially exploitable crash.

CVE-2018-5101: Use-after-free with floating first-letter style elements
A use-after-free vulnerability can occur when manipulating floating first-letter style elements, resulting in a potentially exploitable crash.

CVE-2018-5102: Use-after-free in HTML media elements
A use-after-free vulnerability can occur when manipulating HTML media elements with media streams, resulting in a potentially exploitable crash.

CVE-2018-5103: Use-after-free during mouse event handling
A use-after-free vulnerability can occur during mouse event handling due to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 58.");

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

if (version_is_less(version: version, test_version: "58")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "58", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
