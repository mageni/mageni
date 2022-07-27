# OpenVAS Vulnerability Test
# $Id: deb_3803.nasl 14280 2019-03-18 14:50:45Z cfischer $
# Auto-generated from advisory DSA 3803-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703803");
  script_version("$Revision: 14280 $");
  script_cve_id("CVE-2016-10243");
  script_name("Debian Security Advisory DSA 3803-1 (texlive-base - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:50:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-03-08 00:00:00 +0100 (Wed, 08 Mar 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3803.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|8)");
  script_tag(name:"affected", value:"texlive-base on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie), this problem has been fixed in
version 2014.20141024-2+deb8u1.

For the upcoming stable distribution (stretch), this problem has been
fixed in version 2016.20161130-1.

For the unstable distribution (sid), this problem has been fixed in
version 2016.20161130-1.

We recommend that you upgrade your texlive-base packages.");
  script_tag(name:"summary", value:"It was discovered that texlive-base, the TeX Live package which provides
the essential TeX programs and files, whitelists mpost as an external
program to be run from within the TeX source code (called \write18).
Since mpost allows to specify other programs to be run, an attacker can
take advantage of this flaw for arbitrary code execution when compiling
a TeX document.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"luasseq", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-base", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-fonts-recommended", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-fonts-recommended-doc", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-full", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-generic-recommended", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-latex-base", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-latex-base-doc", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-latex-recommended", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-latex-recommended-doc", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-luatex", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-metapost", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-metapost-doc", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-omega", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-pictures", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-pictures-doc", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-xetex", ver:"2016.20161130-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"latex-beamer", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"latex-xcolor", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pgf", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-base", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-fonts-recommended", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-fonts-recommended-doc", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-full", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-generic-recommended", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-latex-base", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-latex-base-doc", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-latex-recommended", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-latex-recommended-doc", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-luatex", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-metapost", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-metapost-doc", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-omega", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-pictures", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-pictures-doc", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"texlive-xetex", ver:"2014.20141024-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}