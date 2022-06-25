# OpenVAS Vulnerability Test
# $Id: deb_2699.nasl 14276 2019-03-18 14:43:56Z cfischer $
# Auto-generated from advisory DSA 2699-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.892699");
  script_version("$Revision: 14276 $");
  script_cve_id("CVE-2013-1677", "CVE-2013-0776", "CVE-2013-1674", "CVE-2013-0787", "CVE-2013-0780", "CVE-2013-0775", "CVE-2013-1675", "CVE-2013-1678", "CVE-2013-0782", "CVE-2013-1676", "CVE-2013-0795", "CVE-2013-0801", "CVE-2013-1681", "CVE-2013-0800", "CVE-2013-0793", "CVE-2013-0796", "CVE-2013-1679", "CVE-2013-0788", "CVE-2013-1680", "CVE-2013-0783", "CVE-2013-0773", "CVE-2013-1670");
  script_name("Debian Security Advisory DSA 2699-1 (iceweasel - several vulnerabilities)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-06-02 00:00:00 +0200 (Sun, 02 Jun 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2699.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"iceweasel on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 17.0.6esr-1~deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 17.0.6esr-1.

We recommend that you upgrade your iceweasel packages.");
  script_tag(name:"summary", value:"Multiple security issues have been found in Iceweasel, Debian's version
of the Mozilla Firefox web browser: Multiple memory safety errors,
missing input sanitising vulnerabilities, use-after-free vulnerabilities,
buffer overflows and other programming errors may lead to the execution
of arbitrary code, privilege escalation, information leaks or
cross-site-scripting.

We're changing the approach for security updates for Iceweasel, Icedove
and Iceape in stable-security: Instead of backporting security fixes,
we now provide releases based on the Extended Support Release branch. As
such, this update introduces packages based on Firefox 17 and at some
point in the future we will switch to the next ESR branch once ESR 17
has reached it's end of life.

Some Xul extensions currently packaged in the Debian archive are not
compatible with the new browser engine.

A solution to keep packaged extensions compatible with
the Mozilla releases is still being sorted out.

We don't have the resources to backport security fixes to the Iceweasel
release in oldstable-security any longer. If you're up to the task and
want to help, please get in touch with team@security.debian.org.
Otherwise, we'll announce the end of security support for Iceweasel,
Icedove and Iceape in Squeeze in the next update round.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"iceweasel", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ach", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-af", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ak", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-all", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ar", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-as", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ast", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-be", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-bg", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-bn-bd", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-bn-in", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-br", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-bs", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ca", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-cs", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-csb", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-cy", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-da", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-de", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-el", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-en-gb", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-en-za", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-eo", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-es-ar", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-es-cl", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-es-es", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-es-mx", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-et", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-eu", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-fa", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ff", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-fi", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-fr", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-fy-nl", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ga-ie", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-gd", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-gl", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-gu-in", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-he", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hi-in", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hr", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hu", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-hy-am", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-id", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-is", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-it", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ja", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-kk", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-km", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-kn", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ko", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ku", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-lg", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-lij", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-lt", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-lv", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-mai", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-mk", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ml", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-mr", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-nb-no", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-nl", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-nn-no", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-nso", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-or", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-pa-in", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-pl", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-pt-br", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-pt-pt", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-rm", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ro", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ru", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-si", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sk", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sl", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-son", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sq", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sr", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-sv-se", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ta", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-ta-lk", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-te", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-th", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-tr", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-uk", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-vi", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-zh-cn", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-zh-tw", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-l10n-zu", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmozjs-dev", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmozjs10d", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmozjs10d-dbg", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmozjs17d", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmozjs17d-dbg", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xulrunner-10.0", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xulrunner-10.0-dbg", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xulrunner-17.0", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xulrunner-17.0-dbg", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"17.0.6esr-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}