# OpenVAS Vulnerability Test
# $Id: deb_3187.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3187-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703187");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2419",
                  "CVE-2014-6585", "CVE-2014-6591", "CVE-2014-7923", "CVE-2014-7926",
                  "CVE-2014-7940", "CVE-2014-9654");
  script_name("Debian Security Advisory DSA 3187-1 (icu - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-03-15 00:00:00 +0100 (Sun, 15 Mar 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3187.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"icu on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
these problems have been fixed in version 4.8.1.1-12+deb7u2.

For the upcoming stable (jessie) and unstable (sid) distributions, these
problems have been fixed in version 52.1-7.1.

We recommend that you upgrade your icu packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered
in the International Components for Unicode (ICU) library.

CVE-2013-1569
Glyph table issue.

CVE-2013-2383
Glyph table issue.

CVE-2013-2384
Font layout issue.

CVE-2013-2419
Font processing issue.

CVE-2014-6585
Out-of-bounds read.

CVE-2014-6591
Additional out-of-bounds reads.

CVE-2014-7923
Memory corruption in regular expression comparison.

CVE-2014-7926
Memory corruption in regular expression comparison.

CVE-2014-7940
Uninitialized memory.

CVE-2014-9654
More regular expression flaws.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"icu-doc", ver:"4.8.1.1-12+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libicu-dev", ver:"4.8.1.1-12+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libicu48:amd64", ver:"4.8.1.1-12+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libicu48:i386", ver:"4.8.1.1-12+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libicu48-dbg", ver:"4.8.1.1-12+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}