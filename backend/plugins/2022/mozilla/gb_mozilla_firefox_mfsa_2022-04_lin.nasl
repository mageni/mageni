# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2022.04");
  script_cve_id("CVE-2022-0511", "CVE-2022-22753", "CVE-2022-22754", "CVE-2022-22755", "CVE-2022-22756", "CVE-2022-22757", "CVE-2022-22758", "CVE-2022-22759", "CVE-2022-22760", "CVE-2022-22761", "CVE-2022-22762", "CVE-2022-22764");
  script_tag(name:"creation_date", value:"2022-02-09 13:04:21 +0000 (Wed, 09 Feb 2022)");
  script_version("2022-02-09T13:04:21+0000");
  script_tag(name:"last_modification", value:"2022-02-10 11:02:19 +0000 (Thu, 10 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-02-09 13:04:21 +0000 (Wed, 09 Feb 2022)");

  script_name("Mozilla Firefox Security Advisory (MFSA2022-04) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2022-04");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-04/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1713579%2C1735448%2C1743821%2C1746313%2C1746314%2C1746316%2C1746321%2C1746322%2C1746323%2C1746412%2C1746430%2C1746451%2C1746488%2C1746875%2C1746898%2C1746905%2C1746907%2C1746917%2C1747128%2C1747137%2C1747331%2C1747346%2C1747439%2C1747457%2C1747870%2C1749051%2C1749274%2C1749831");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1742682%2C1744165%2C1746545%2C1748210%2C1748279");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1309630");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1317873");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1720098");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1728742");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1732435");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1739957");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1740985");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1743931");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1745566");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1748503");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1750565");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2022-22753: Privilege Escalation to SYSTEM on Windows via Maintenance Service
A Time-of-Check Time-of-Use bug existed in the Maintenance (Updater) Service that could be abused to grant Users write access to an arbitrary directory. This could have been used to escalate to SYSTEM access.This bug only affects Firefox on Windows. Other operating systems are unaffected.

CVE-2022-22754: Extensions could have bypassed permission confirmation during update
If a user installed an extension of a particular type, the extension could have auto-updated itself and while doing so, bypass the prompt which grants the new version the new requested permissions.

CVE-2022-22755: XSL could have allowed JavaScript execution after a tab was closed
By using XSL Transforms, a malicious webserver could have served a user an XSL document that would continue to execute JavaScript (within the bounds of the same-origin policy) even after the tab was closed.

CVE-2022-22756: Drag and dropping an image could have resulted in the dropped object being an executable
If a user was convinced to drag and drop an image to their desktop or other folder, the resulting object could have been changed into an executable script which would have run arbitrary code after the user clicked on it.

CVE-2022-22757: Remote Agent did not prevent local websites from connecting
Remote Agent, used in WebDriver, did not validate the Host or Origin headers. This could have allowed websites to connect back locally to the user's browser to control it. This bug only affected Firefox when WebDriver was enabled, which is not the default configuration.

CVE-2022-22758: tel: links could have sent USSD codes to the dialer on Firefox for Android
When clicking on a tel: link, USSD codes, specified after a character, would be included in the phone number. On certain phones, or on certain carriers, if the number was dialed this could perform actions on a user's account, similar to a cross-site request forgery attack.This bug only affects Firefox for Android. Other operating systems are unaffected.*

CVE-2022-22759: Sandboxed iframes could have executed script if the parent appended elements
If a document created a sandboxed iframe without allow-scripts, and subsequently appended an element to the iframe's document that e.g. had a JavaScript event handler - the event handler would have run despite the iframe's sandbox.

CVE-2022-22760: Cross-Origin responses could be distinguished between script and non-script content-types
When importing resources using Web Workers, error messages would distinguish the difference between application/javascript responses and non-script responses. This could have been abused to learn information cross-origin.

CVE-2022-22761: frame-ancestors Content Security Policy directive was not enforced for framed extension pages
Web-accessible extension pages (pages with a moz-extension:// scheme) were not ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 97.");

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

if (version_is_less(version: version, test_version: "97")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "97", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
