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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2017.10");
  script_cve_id("CVE-2016-10195", "CVE-2016-10196", "CVE-2016-10197", "CVE-2016-6354", "CVE-2017-5429", "CVE-2017-5430", "CVE-2017-5432", "CVE-2017-5433", "CVE-2017-5434", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441", "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5448", "CVE-2017-5449", "CVE-2017-5450", "CVE-2017-5451", "CVE-2017-5452", "CVE-2017-5453", "CVE-2017-5454", "CVE-2017-5455", "CVE-2017-5456", "CVE-2017-5458", "CVE-2017-5459", "CVE-2017-5460", "CVE-2017-5461", "CVE-2017-5462", "CVE-2017-5463", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5466", "CVE-2017-5467", "CVE-2017-5468", "CVE-2017-5469");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 01:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Mozilla Firefox Security Advisory (MFSA2017-10) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2017-10");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-10/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1342101%2C1340482%2C1344686%2C1329796%2C1346419%2C1349621%2C1344081%2C1344305%2C1348143%2C1349719%2C1353476%2C1337418%2C1346140%2C1339722");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1343261%2C1350844%2C1341096%2C1342823%2C1348894%2C1348941%2C1349340%2C1352926%2C1353088%2C");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1229426");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1273537");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1292534");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1321247");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1325955");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1329521");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1333858");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1336828");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1336830");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1336832");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1338867");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1340127");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1341191");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1342661");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1343453");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1343505");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1343552");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1343642");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1343795");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1344380");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1344415");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1344461");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1344467");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1344517");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1345089");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1345461");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1346648");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1346654");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1347075");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1347168");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1347262");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1347617");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1347979");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1349276");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1349946");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1350683");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1353975");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2017-5433: Use-after-free in SMIL animation functions
A use-after-free vulnerability in SMIL animation functions occurs when pointers to animation elements in an array are dropped from the animation controller while still in use. This results in a potentially exploitable crash.

CVE-2017-5435: Use-after-free during transaction processing in the editor
A use-after-free vulnerability occurs during transaction processing in the editor during design mode interactions. This results in a potentially exploitable crash.

CVE-2017-5436: Out-of-bounds write with malicious font in Graphite 2
An out-of-bounds write in the Graphite 2 library triggered with a maliciously crafted Graphite font. This results in a potentially exploitable crash. This issue was fixed in the Graphite 2 library as well as Mozilla products.

CVE-2017-5461: Out-of-bounds write in Base64 encoding in NSS
An out-of-bounds write during Base64 decoding operation in the Network Security Services (NSS) library due to insufficient memory being allocated to the buffer. This results in a potentially exploitable crash. The NSS library has been updated to fix this issue to address this issue and Firefox 53 has been updated with NSS version 3.29.5.

CVE-2017-5459: Buffer overflow in WebGL
A buffer overflow in WebGL triggerable by web content, resulting in a potentially exploitable crash.

CVE-2017-5466: Origin confusion when reloading isolated data:text/html URL
If a page is loaded from an original site through a hyperlink and contains a redirect to a data:text/html URL, triggering a reload will run the reloaded data:text/html page with its origin set incorrectly. This allows for a cross-site scripting (XSS) attack.

CVE-2017-5434: Use-after-free during focus handling
A use-after-free vulnerability occurs when redirecting focus handling which results in a potentially exploitable crash.

CVE-2017-5432: Use-after-free in text input selection
A use-after-free vulnerability occurs during certain text input selection resulting in a potentially exploitable crash.

CVE-2017-5460: Use-after-free in frame selection
A use-after-free vulnerability in frame selection triggered by a combination of malicious script content and key presses by a user. This results in a potentially exploitable crash.

CVE-2017-5438: Use-after-free in nsAutoPtr during XSLT processing
A use-after-free vulnerability during XSLT processing due to the result handler being held by a freed handler during handling. This results in a potentially exploitable crash.

CVE-2017-5439: Use-after-free in nsTArray Length() during XSLT processing
A use-after-free vulnerability during XSLT processing due to poor handling of template parameters. This results in a potentially exploitable crash.

CVE-2017-5440: Use-after-free in txExecutionState destructor during XSLT processing
A use-after-free vulnerability during XSLT processing due to a failure to propagate error ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 53.");

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

if (version_is_less(version: version, test_version: "53")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "53", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
