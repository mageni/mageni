# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892279");
  script_version("2020-07-17T12:33:41+0000");
  script_cve_id("CVE-2020-11996", "CVE-2020-9484");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-07-20 10:03:49 +0000 (Mon, 20 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-17 12:33:41 +0000 (Fri, 17 Jul 2020)");
  script_name("Debian LTS: Security Advisory for tomcat8 (DLA-2279-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00010.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2279-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/961209");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat8'
  package(s) announced via the DLA-2279-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in the Tomcat
servlet and JSP engine.

CVE-2020-9484

When using Apache Tomcat and an attacker is able to control the
contents and name of a file on the server, and b) the server is
configured to use the PersistenceManager with a FileStore, and c)
the PersistenceManager is configured with
sessionAttributeValueClassNameFilter='null' (the default unless a
SecurityManager is used) or a sufficiently lax filter to allow the
attacker provided object to be deserialized, and d) the attacker
knows the relative file path from the storage location used by
FileStore to the file the attacker has control over, then, using a
specifically crafted request, the attacker will be able to trigger
remote code execution via deserialization of the file under their
control. Note that all of conditions a) to d) must be true for the
attack to succeed.

CVE-2020-11996

A specially crafted sequence of HTTP/2 requests sent to Apache
Tomcat could trigger high CPU usage for several seconds. If a
sufficient number of such requests were made on concurrent HTTP/2
connections, the server could become unresponsive.");

  script_tag(name:"affected", value:"'tomcat8' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
8.5.54-0+deb9u2.

We recommend that you upgrade your tomcat8 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libservlet3.1-java", ver:"8.5.54-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libservlet3.1-java-doc", ver:"8.5.54-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtomcat8-embed-java", ver:"8.5.54-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.5.54-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8", ver:"8.5.54-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-admin", ver:"8.5.54-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-common", ver:"8.5.54-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-docs", ver:"8.5.54-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-examples", ver:"8.5.54-0+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-user", ver:"8.5.54-0+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
