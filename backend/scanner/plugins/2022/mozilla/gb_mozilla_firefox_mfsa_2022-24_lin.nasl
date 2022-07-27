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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2022.24");
  script_cve_id("CVE-2022-2200", "CVE-2022-34468", "CVE-2022-34469", "CVE-2022-34470", "CVE-2022-34471", "CVE-2022-34472", "CVE-2022-34473", "CVE-2022-34474", "CVE-2022-34475", "CVE-2022-34476", "CVE-2022-34477", "CVE-2022-34478", "CVE-2022-34479", "CVE-2022-34480", "CVE-2022-34481", "CVE-2022-34482", "CVE-2022-34483", "CVE-2022-34484", "CVE-2022-34485");
  script_tag(name:"creation_date", value:"2022-06-29 12:38:26 +0000 (Wed, 29 Jun 2022)");
  script_version("2022-06-29T12:38:26+0000");
  script_tag(name:"last_modification", value:"2022-06-29 12:38:26 +0000 (Wed, 29 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-06-29 12:38:26 +0000 (Wed, 29 Jun 2022)");

  script_name("Mozilla Firefox Security Advisory (MFSA2022-24) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2022-24");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-24/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1763634%2C1772651");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1768409%2C1768578");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1335845");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1387919");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1454072");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1483699");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1497246");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1677138");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1721220");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1731614");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1745595");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1757210");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1765951");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1766047");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1768537");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1770123");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1770888");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1771381");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1773717");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=845880");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2022-34479: A popup window could be resized in a way to overlay the address bar with web content
A malicious website that could create a popup could have resized the popup to overlay the address bar with its own content, resulting in potential user confusion or spoofing attacks. This bug only affects Firefox for Linux. Other operating systems are unaffected.

CVE-2022-34470: Use-after-free in nsSHistory
Navigations between XML documents may have led to a use-after-free and potentially exploitable crash.

CVE-2022-34468: CSP sandbox header without `allow-scripts` can be bypassed via retargeted javascript: URI
An iframe that was not permitted to run scripts could do so if the user clicked on a javascript: link.

CVE-2022-34482: Drag and drop of malicious image could have led to malicious executable and potential code execution
An attacker who could have convinced a user to drag and drop an image to a filesystem could have manipulated the resulting filename to contain an executable extension, and by extension potentially tricked the user into executing malicious code. While very similar, this is a separate issue from CVE-2022-34483.

CVE-2022-34483: Drag and drop of malicious image could have led to malicious executable and potential code execution
An attacker who could have convinced a user to drag and drop an image to a filesystem could have manipulated the resulting filename to contain an executable extension, and by extension potentially tricked the user into executing malicious code. While very similar, this is a separate issue from CVE-2022-34482.

CVE-2022-34476: ASN.1 parser could have been tricked into accepting malformed ASN.1
ASN.1 parsing of an indefinite SEQUENCE inside an indefinite GROUP could have resulted in the parser accepting malformed ASN.1.

CVE-2022-34481: Potential integer overflow in ReplaceElementsAt
In the nsTArray_Impl::ReplaceElementsAt() function, an integer overflow could have occurred when the number of elements to replace was too large for the container.

CVE-2022-34474: Sandboxed iframes could redirect to external schemes
Even when an iframe was sandboxed with allow-top-navigation-by-user-activation, if it received a redirect header to an external protocol the browser would process the redirect and prompt the user as appropriate.

CVE-2022-34469: TLS certificate errors on HSTS-protected domains could be bypassed by the user on Firefox for Android
When a TLS Certificate error occurs on a domain protected by the HSTS header, the browser should not allow the user to bypass the certificate error. On Firefox for Android, the user was presented with the option to bypass the error, this could only have been done by the user explicitly. This bug only affects Firefox for Android. Other operating systems are unaffected.

CVE-2022-34471: Compromised server could trick a browser into an addon downgrade
When downloading an update for an addon, the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 102.");

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

if (version_is_less(version: version, test_version: "102")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "102", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
