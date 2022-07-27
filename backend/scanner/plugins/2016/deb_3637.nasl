# OpenVAS Vulnerability Test
# $Id: deb_3637.nasl 3798 2016-08-04 11:01:10Z antu123 $
# Auto-generated from advisory DSA 3637-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703637");
  script_version("$Revision: 14275 $");
  script_cve_id("CVE-2016-1704", "CVE-2016-1705", "CVE-2016-1706", "CVE-2016-1707",
                  "CVE-2016-1708", "CVE-2016-1709", "CVE-2016-1710", "CVE-2016-1711",
                  "CVE-2016-5127", "CVE-2016-5128", "CVE-2016-5129", "CVE-2016-5130",
                  "CVE-2016-5131", "CVE-2016-5132", "CVE-2016-5133", "CVE-2016-5134",
                  "CVE-2016-5135", "CVE-2016-5136", "CVE-2016-5137");
  script_name("Debian Security Advisory DSA 3637-1 (chromium-browser - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-08-04 16:27:39 +0530 (Thu, 04 Aug 2016)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3637.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");
  script_tag(name:"affected", value:"chromium-browser on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
these problems have been fixed in version 52.0.2743.82-1~deb8u1.

For the testing (stretch) and unstable (sid) distributions, these problems
have been fixed in version 52.0.2743.82-1.

We recommend that you upgrade your chromium-browser packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been
discovered in the chromium web browser.

CVE-2016-1704
The chrome development team found and fixed various issues during
internal auditing.

CVE-2016-1705
The chrome development team found and fixed various issues during
internal auditing.

CVE-2016-1706
Pinkie Pie discovered a way to escape the Pepper Plugin API sandbox.

CVE-2016-1707
xisigr discovered a URL spoofing issue.

CVE-2016-1708
Adam Varsan discovered a use-after-free issue.

CVE-2016-1709
ChenQin discovered a buffer overflow issue in the sfntly library.

CVE-2016-1710
Mariusz Mlynski discovered a same-origin bypass.

CVE-2016-1711
Mariusz Mlynski discovered another same-origin bypass.

CVE-2016-5127
cloudfuzzer discovered a use-after-free issue.

CVE-2016-5128
A same-origin bypass issue was discovered in the v8 javascript library.

CVE-2016-5129
Jeonghoon Shin discovered a memory corruption issue in the v8 javascript
library.

CVE-2016-5130
Widih Matar discovered a URL spoofing issue.

CVE-2016-5131
Nick Wellnhofer discovered a use-after-free issue in the libxml2 library.

CVE-2016-5132
Ben Kelly discovered a same-origin bypass.

CVE-2016-5133
Patch Eudor discovered an issue in proxy authentication.

CVE-2016-5134
Paul Stone discovered an information leak in the Proxy Auto-Config
feature.

CVE-2016-5135
ShenYeYinJiu discovered a way to bypass the Content Security Policy.

CVE-2016-5136
Rob Wu discovered a use-after-free issue.

CVE-2016-5137
Xiaoyin Liu discovered a way to discover whether an HSTS web side had been
visited.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chromedriver", ver:"52.0.2743.82-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium", ver:"52.0.2743.82-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-dbg", ver:"52.0.2743.82-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-inspector", ver:"52.0.2743.82-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"52.0.2743.82-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromedriver", ver:"52.0.2743.82-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium", ver:"52.0.2743.82-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"52.0.2743.82-1", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}