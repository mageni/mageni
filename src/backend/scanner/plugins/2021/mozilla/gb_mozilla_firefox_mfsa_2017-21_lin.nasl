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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2017.21");
  script_cve_id("CVE-2017-7793", "CVE-2017-7805", "CVE-2017-7810", "CVE-2017-7811", "CVE-2017-7812", "CVE-2017-7813", "CVE-2017-7814", "CVE-2017-7815", "CVE-2017-7816", "CVE-2017-7817", "CVE-2017-7818", "CVE-2017-7819", "CVE-2017-7820", "CVE-2017-7821", "CVE-2017-7822", "CVE-2017-7823", "CVE-2017-7824", "CVE-2017-7825");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-09 14:14:00 +0000 (Thu, 09 Aug 2018)");

  script_name("Mozilla Firefox Security Advisory (MFSA2017-21) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2017-21");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-21/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1386787%2C1389974%2C1371657%2C1360334%2C1390550%2C1380824%2C1387918%2C1395598");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1392105%2C1395919%2C1388113%2C1348955%2C1394522%2C1387659%2C1369560%2C1388045%2C1378658%2C1379414%2C1385112%2C1367497");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1346515");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1356596");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1363723");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1368859");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1368981");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1371889");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1376036");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1377618");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1378207");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1379842");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1380292");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1380597");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1383951");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1390980");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1393624");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1396320");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1398381");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2017-7793: Use-after-free with Fetch API
A use-after-free vulnerability can occur in the Fetch API when the worker or the associated window are freed when still in use, resulting in a potentially exploitable crash.

CVE-2017-7817: Firefox for Android address bar spoofing through fullscreen mode
A spoofing vulnerability can occur when a page switches to fullscreen mode without user notification, allowing a fake address bar to be displayed. This allows an attacker to spoof which page is actually loaded and in use. Note: This attack only affects Firefox for Android. Other operating systems are not affected.

CVE-2017-7818: Use-after-free during ARIA array manipulation
A use-after-free vulnerability can occur when manipulating arrays of Accessible Rich Internet Applications (ARIA) elements within containers through the DOM. This results in a potentially exploitable crash.

CVE-2017-7819: Use-after-free while resizing images in design mode
A use-after-free vulnerability can occur in design mode when image objects are resized if objects referenced during the resizing have been freed from memory. This results in a potentially exploitable crash.

CVE-2017-7824: Buffer overflow when drawing and validating elements with ANGLE
A buffer overflow occurs when drawing and validating elements with the ANGLE graphics library, used for WebGL content. This is due to an incorrect value being passed within the library during checks and results in a potentially exploitable crash.

CVE-2017-7805: Use-after-free in TLS 1.2 generating handshake hashes
During TLS 1.2 exchanges, handshake hashes are generated which point to a message buffer. This saved data is used for later messages but in some cases, the handshake transcript can exceed the space available in the current buffer, causing the allocation of a new buffer. This leaves a pointer pointing to the old, freed buffer, resulting in a use-after-free when handshake hashes are then calculated afterwards. This can result in a potentially exploitable crash.

CVE-2017-7812: Drag and drop of malicious page content to the tab bar can open locally stored files
If web content on a page is dragged onto portions of the browser UI, such as the tab bar, links can be opened that otherwise would not be allowed to open. This can allow malicious web content to open a locally stored file through file: URLs.

CVE-2017-7814: Blob and data URLs bypass phishing and malware protection warnings
File downloads encoded with blob: and data: URL elements bypassed normal file download checks though the Phishing and Malware Protection feature and its block lists of suspicious sites and files. This would allow malicious sites to lure users into downloading executables that would otherwise be detected as suspicious.

CVE-2017-7813: Integer truncation in the JavaScript parser
Inside the JavaScript parser, a cast of an integer to a narrower type can result in data read ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 56.");

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

if (version_is_less(version: version, test_version: "56")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "56", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
