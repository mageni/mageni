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
  script_oid("1.3.6.1.4.1.25623.1.0.891853");
  script_version("2019-07-14T02:00:12+0000");
  script_cve_id("CVE-2014-3578", "CVE-2014-3625", "CVE-2015-3192", "CVE-2015-5211", "CVE-2016-9878");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-14 02:00:12 +0000 (Sun, 14 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-14 02:00:12 +0000 (Sun, 14 Jul 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1853-1] libspring-java security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/07/msg00012.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1853-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/760733");
  script_xref(name:"URL", value:"https://bugs.debian.org/769698");
  script_xref(name:"URL", value:"https://bugs.debian.org/796137");
  script_xref(name:"URL", value:"https://bugs.debian.org/849167");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libspring-java'
  package(s) announced via the DSA-1853-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vulnerabilities have been identified in libspring-java, a modular
Java/J2EE application framework.

CVE-2014-3578

A directory traversal vulnerability that allows remote attackers to
read arbitrary files via a crafted URL.

CVE-2014-3625

A directory traversal vulnerability that allows remote attackers to
read arbitrary files via unspecified vectors, related to static
resource handling.

CVE-2015-3192

Improper processing of inline DTD declarations when DTD is not
entirely disabled, which allows remote attackers to cause a denial
of service (memory consumption and out-of-memory errors) via a
crafted XML file.

CVE-2015-5211

Reflected File Download (RFD) attack vulnerability, which allows a
malicious user to craft a URL with a batch script extension that
results in the response being downloaded rather than rendered and
also includes some input reflected in the response.

CVE-2016-9878

Improper path sanitization in ResourceServlet, which allows
directory traversal attacks.");

  script_tag(name:"affected", value:"'libspring-java' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.0.6.RELEASE-17+deb8u1.

We recommend that you upgrade your libspring-java packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libspring-aop-java", ver:"3.0.6.RELEASE-17+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-beans-java", ver:"3.0.6.RELEASE-17+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-context-java", ver:"3.0.6.RELEASE-17+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-context-support-java", ver:"3.0.6.RELEASE-17+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-core-java", ver:"3.0.6.RELEASE-17+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-expression-java", ver:"3.0.6.RELEASE-17+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-instrument-java", ver:"3.0.6.RELEASE-17+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-jdbc-java", ver:"3.0.6.RELEASE-17+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-jms-java", ver:"3.0.6.RELEASE-17+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-orm-java", ver:"3.0.6.RELEASE-17+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-oxm-java", ver:"3.0.6.RELEASE-17+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-test-java", ver:"3.0.6.RELEASE-17+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-transaction-java", ver:"3.0.6.RELEASE-17+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-web-java", ver:"3.0.6.RELEASE-17+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-web-portlet-java", ver:"3.0.6.RELEASE-17+deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-web-servlet-java", ver:"3.0.6.RELEASE-17+deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);