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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2017.05");
  script_cve_id("CVE-2017-5398", "CVE-2017-5399", "CVE-2017-5400", "CVE-2017-5401", "CVE-2017-5402", "CVE-2017-5403", "CVE-2017-5404", "CVE-2017-5405", "CVE-2017-5406", "CVE-2017-5407", "CVE-2017-5408", "CVE-2017-5409", "CVE-2017-5410", "CVE-2017-5411", "CVE-2017-5412", "CVE-2017-5413", "CVE-2017-5414", "CVE-2017-5415", "CVE-2017-5416", "CVE-2017-5417", "CVE-2017-5418", "CVE-2017-5419", "CVE-2017-5420", "CVE-2017-5421", "CVE-2017-5422", "CVE-2017-5425", "CVE-2017-5426", "CVE-2017-5427");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 10:05:00 +0000 (Wed, 01 Aug 2018)");

  script_name("Mozilla Firefox Security Advisory (MFSA2017-05) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2017-05");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-05/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1332550%2C1332597%2C1338383%2C1321612%2C1322971%2C1333568%2C1333887%2C1335450%2C1325052%2C1324379%2C1336510");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1332569%2C1315248%2C1261335%2C1321038%2C1331771%2C1339566%2C1339591%2C1240893%2C1341905%2C1323241%2C1336467%2C1270288%2C1295299%2C1296024%2C1304201%2C1306142%2C1307557%2C1308036%2C1334246%2C1334290%2C1317085%2C1339116%2C1324000%2C1323150%2C1332501%2C1320894%2C1333752%2C1303713%2C1321566%2C1264053%2C1343513");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1257361");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1284395");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1295002");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1295542");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1301876");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1306890");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1312243");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1313711");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1319370");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1321719");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1321814");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1322716");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1325511");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1328121");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1328323");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1328861");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1330687");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1334876");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1334933");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1336622");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1336699");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1337504");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1338876");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1340138");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1340186");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=791597");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2017-5400: asm.js JIT-spray bypass of ASLR and DEP
JIT-spray targeting asm.js combined with a heap spray allows for a bypass of ASLR and DEP protections leading to potential memory corruption attacks.

CVE-2017-5401: Memory Corruption when handling ErrorResult
A crash triggerable by web content in which an ErrorResult references unassigned memory due to a logic error. The resulting crash may be exploitable.

CVE-2017-5402: Use-after-free working with events in FontFace objects
A use-after-free can occur when events are fired for a FontFace object after the object has been already been destroyed while working with fonts. This results in a potentially exploitable crash.

CVE-2017-5403: Use-after-free using addRange to add range to an incorrect root object
When adding a range to an object in the DOM, it is possible to use addRange to add the range to an incorrect root object. This triggers a use-after-free, resulting in a potentially exploitable crash.

CVE-2017-5404: Use-after-free working with ranges in selections
A use-after-free error can occur when manipulating ranges in selections with one node inside a native anonymous tree and one node outside of it. This results in a potentially exploitable crash.

CVE-2017-5406: Segmentation fault in Skia with canvas operations
A segmentation fault can occur in the Skia graphics library during some canvas operations due to issues with mask/clip intersection and empty masks.

CVE-2017-5407: Pixel and history stealing via floating-point timing side channel with SVG filters
Using SVG filters that don't use the fixed point math implementation on a target iframe, a malicious page can extract pixel values from a targeted user. This can be used to extract history information and read text values across domains. This violates same-origin policy and leads to information disclosure.

CVE-2017-5410: Memory corruption during JavaScript garbage collection incremental sweeping
Memory corruption resulting in a potentially exploitable crash during garbage collection of JavaScript due errors in how incremental sweeping is managed for memory cleanup.

CVE-2017-5411: Use-after-free in Buffer Storage in libGLES
A use-after-free can occur during buffer storage operations within the ANGLE graphics library, used for WebGL content. The buffer storage can be freed while still in use in some circumstances, leading to a potentially exploitable crash. Note: This issue is in libGLES, which is only in use on Windows. Other operating systems are not affected.

CVE-2017-5409: File deletion via callback parameter in Mozilla Windows Updater and Maintenance Service
The Mozilla Windows updater can be called by a non-privileged user to delete an arbitrary local file by passing a special path to the callback parameter through the Mozilla Maintenance Service, which has privileged access. Note: This attack requires local system access and only affects Windows. Other ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 52.");

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

if (version_is_less(version: version, test_version: "52")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "52", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
