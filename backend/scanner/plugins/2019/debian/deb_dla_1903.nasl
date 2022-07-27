# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891903");
  script_version("2019-08-30T02:00:13+0000");
  script_cve_id("CVE-2018-11782", "CVE-2019-0203");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-08-30 02:00:13 +0000 (Fri, 30 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-30 02:00:13 +0000 (Fri, 30 Aug 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1903-1] subversion security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00037.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1903-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'subversion'
  package(s) announced via the DSA-1903-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Subversion, a version control
system. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2018-11782

Ace Olszowka reported that the Subversion's svnserve server process
may exit when a well-formed read-only request produces a particular
answer, leading to a denial of service.

CVE-2019-0203

Tomas Bortoli reported that the Subversion's svnserve server process
may exit when a client sends certain sequences of protocol commands.
If the server is configured with anonymous access enabled this could
lead to a remote unauthenticated denial of service.");

  script_tag(name:"affected", value:"'subversion' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1.8.10-6+deb8u7.

We recommend that you upgrade your subversion packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-svn", ver:"1.8.10-6+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.8.10-6+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsvn-dev", ver:"1.8.10-6+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsvn-doc", ver:"1.8.10-6+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsvn-java", ver:"1.8.10-6+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsvn-perl", ver:"1.8.10-6+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsvn-ruby1.8", ver:"1.8.10-6+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsvn1", ver:"1.8.10-6+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-subversion", ver:"1.8.10-6+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby-svn", ver:"1.8.10-6+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"subversion", ver:"1.8.10-6+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"subversion-dbg", ver:"1.8.10-6+deb8u7", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"subversion-tools", ver:"1.8.10-6+deb8u7", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);