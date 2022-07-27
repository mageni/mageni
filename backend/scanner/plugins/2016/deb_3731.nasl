# OpenVAS Vulnerability Test
# $Id: deb_3731.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Auto-generated from advisory DSA 3731-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703731");
  script_version("$Revision: 14275 $");
  script_cve_id("CVE-2016-5181", "CVE-2016-5182", "CVE-2016-5183", "CVE-2016-5184",
                  "CVE-2016-5185", "CVE-2016-5186", "CVE-2016-5187", "CVE-2016-5188",
                  "CVE-2016-5189", "CVE-2016-5190", "CVE-2016-5191", "CVE-2016-5192",
                  "CVE-2016-5193", "CVE-2016-5194", "CVE-2016-5198", "CVE-2016-5199",
                  "CVE-2016-5200", "CVE-2016-5201", "CVE-2016-5202", "CVE-2016-5203",
                  "CVE-2016-5204", "CVE-2016-5205", "CVE-2016-5206", "CVE-2016-5207",
                  "CVE-2016-5208", "CVE-2016-5209", "CVE-2016-5210", "CVE-2016-5211",
                  "CVE-2016-5212", "CVE-2016-5213", "CVE-2016-5214", "CVE-2016-5215",
                  "CVE-2016-5216", "CVE-2016-5217", "CVE-2016-5218", "CVE-2016-5219",
                  "CVE-2016-5220", "CVE-2016-5221", "CVE-2016-5222", "CVE-2016-5223",
                  "CVE-2016-5224", "CVE-2016-5225", "CVE-2016-5226", "CVE-2016-9650",
                  "CVE-2016-9651", "CVE-2016-9652");
  script_name("Debian Security Advisory DSA 3731-1 (chromium-browser - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-12-11 00:00:00 +0100 (Sun, 11 Dec 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3731.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
these problems have been fixed in version 55.0.2883.75-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 55.0.2883.75-1.

We recommend that you upgrade your chromium-browser packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been
discovered in the chromium web browser.

CVE-2016-5181
A cross-site scripting issue was discovered.

CVE-2016-5182
Giwan Go discovered a heap overflow issue.

CVE-2016-5183
A use-after-free issue was discovered in the pdfium library.

CVE-2016-5184
Another use-after-free issue was discovered in the pdfium library.

CVE-2016-5185
cloudfuzzer discovered a use-after-free issue in Blink/Webkit.

CVE-2016-5186
Abdulrahman Alqabandi discovered an out-of-bounds read issue in the
developer tools.

CVE-2016-5187
Luan Herrera discovered a URL spoofing issue.

Description truncated. Please see the references for more information.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chromedriver", ver:"55.0.2883.75-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium", ver:"55.0.2883.75-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-dbg", ver:"55.0.2883.75-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-inspector", ver:"55.0.2883.75-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"55.0.2883.75-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}