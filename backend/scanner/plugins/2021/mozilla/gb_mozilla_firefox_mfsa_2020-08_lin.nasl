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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2020.08");
  script_cve_id("CVE-2019-20503", "CVE-2020-6805", "CVE-2020-6806", "CVE-2020-6807", "CVE-2020-6808", "CVE-2020-6809", "CVE-2020-6810", "CVE-2020-6811", "CVE-2020-6812", "CVE-2020-6813", "CVE-2020-6814", "CVE-2020-6815");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-22 18:15:00 +0000 (Wed, 22 Apr 2020)");

  script_name("Mozilla Firefox Security Advisory (MFSA2020-08) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2020-08");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-08/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1181957%2C1557732%2C1557739%2C1611457%2C1612431");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1592078%2C1604847%2C1608256%2C1612636%2C1614339");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1247968");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1420296");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1432856");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1605814");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1607742");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1610880");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1612308");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1613765");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1614971");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1616661");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2020-6805: Use-after-free when removing data about origins
When removing data about an origin whose tab was recently closed, a use-after-free could occur in the Quota manager, resulting in a potentially exploitable crash.

CVE-2020-6806: BodyStream::OnInputStreamReady was missing protections against state confusion
By carefully crafting promise resolutions, it was possible to cause an out-of-bounds read off the end of an array resized during script execution. This could have led to memory corruption and a potentially exploitable crash.

CVE-2020-6807: Use-after-free in cubeb during stream destruction
When a device was changed while a stream was about to be destroyed, the stream-reinit task may have been executed after the stream was destroyed, causing a use-after-free and a potentially exploitable crash.

CVE-2020-6808: URL Spoofing via javascript: URL
When a JavaScript URL (javascript:) is evaluated and the result is a string, this string is parsed to create an HTML document, which is then presented. Previously, this document's URL (as reported by the document.location property, for example) was the originating javascript: URL which could lead to spoofing attacks, it is now correctly the URL of the originating document.

CVE-2020-6809: Web Extensions with the all-urls permission could access local files
When a Web Extension had the all-urls permission and made a fetch request with a mode set to 'same-origin', it was possible for the Web Extension to read local files.

CVE-2020-6810: Focusing a popup while in fullscreen could have obscured the fullscreen notification
After a website had entered fullscreen mode, it could have used a previously opened popup to obscure the notification that indicates the browser is in fullscreen mode. Combined with spoofing the browser chrome, this could have led to confusing the user about the current origin of the page and credential theft or other attacks.

CVE-2020-6811: Devtools' 'Copy as cURL' feature did not fully escape website-controlled data, potentially leading to command injection
The 'Copy as cURL' feature of Devtools' network tab did not properly escape the HTTP method of a request, which can be controlled by the website. If a user used the 'Copy as Curl' feature and pasted the command into a terminal, it could have resulted in command injection and arbitrary command execution.

CVE-2019-20503: Out of bounds reads in sctp_load_addresses_from_init
The inputs to sctp_load_addresses_from_init are verified by sctp_arethere_unrecognized_parameters, however, the two functions handled parameter bounds differently, resulting in out of bounds reads when parameters are partially outside a chunk.

CVE-2020-6812: The names of AirPods with personally identifiable information were exposed to websites with camera or microphone permission
The first time AirPods are connected to an iPhone, they become named after the user's name by default ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 74.");

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

if (version_is_less(version: version, test_version: "74")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "74", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
