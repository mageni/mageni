# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892133");
  script_version("2020-03-05T04:00:06+0000");
  script_cve_id("CVE-2019-17569", "CVE-2020-1935", "CVE-2020-1938");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-03-05 04:00:06 +0000 (Thu, 05 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-05 04:00:06 +0000 (Thu, 05 Mar 2020)");
  script_name("Debian LTS: Security Advisory for tomcat7 (DLA-2133-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/03/msg00006.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2133-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat7'
  package(s) announced via the DLA-2133-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in the Tomcat
servlet and JSP engine.

CVE-2019-17569

The refactoring in 7.0.98 introduced a regression. The result of
the regression was that invalid Transfer-Encoding headers were
incorrectly processed leading to a possibility of HTTP Request
Smuggling if Tomcat was located behind a reverse proxy that
incorrectly handled the invalid Transfer-Encoding header in a
particular manner. Such a reverse proxy is considered unlikely.

CVE-2020-1935

The HTTP header parsing code used an approach to end-of-line (EOL)
parsing that allowed some invalid HTTP headers to be parsed as
valid. This led to a possibility of HTTP Request Smuggling if Tomcat
was located behind a reverse proxy that incorrectly handled the
invalid Transfer-Encoding header in a particular manner. Such a
reverse proxy is considered unlikely.

CVE-2020-1938

When using the Apache JServ Protocol (AJP), care must be taken when
trusting incoming connections to Apache Tomcat. Tomcat treats AJP
connections as having higher trust than, for example, a similar HTTP
connection. If such connections are available to an attacker, they
can be exploited in ways that may be surprising. Prior to Tomcat
7.0.100, Tomcat shipped with an AJP Connector enabled by default
that listened on all configured IP addresses. It was expected (and
recommended in the security guide) that this Connector would be
disabled if not required.

Note that Debian already disabled the AJP connector by default.
Mitigation is only required if the AJP port was made accessible to
untrusted users.");

  script_tag(name:"affected", value:"'tomcat7' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
7.0.56-3+really7.0.100-1.

We recommend that you upgrade your tomcat7 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libservlet3.0-java", ver:"7.0.56-3+really7.0.100-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libservlet3.0-java-doc", ver:"7.0.56-3+really7.0.100-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.56-3+really7.0.100-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7", ver:"7.0.56-3+really7.0.100-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7-admin", ver:"7.0.56-3+really7.0.100-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7-common", ver:"7.0.56-3+really7.0.100-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7-docs", ver:"7.0.56-3+really7.0.100-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7-examples", ver:"7.0.56-3+really7.0.100-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat7-user", ver:"7.0.56-3+really7.0.100-1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
