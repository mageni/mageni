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
  script_oid("1.3.6.1.4.1.25623.1.0.892209");
  script_version("2020-05-29T03:00:12+0000");
  script_cve_id("CVE-2019-17563", "CVE-2020-1935", "CVE-2020-1938", "CVE-2020-9484");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-05-29 08:52:53 +0000 (Fri, 29 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-29 03:00:12 +0000 (Fri, 29 May 2020)");
  script_name("Debian LTS: Security Advisory for tomcat8 (DLA-2209-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/05/msg00026.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2209-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/961209");
  script_xref(name:"URL", value:"https://bugs.debian.org/952436");
  script_xref(name:"URL", value:"https://bugs.debian.org/952437");
  script_xref(name:"URL", value:"https://bugs.debian.org/952438");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat8'
  package(s) announced via the DLA-2209-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in the Tomcat
servlet and JSP engine.

WARNING: The fix for CVE-2020-1938 may disrupt services that rely on a
working AJP configuration. The option secretRequired defaults to true
now. You should define a secret in your server.xml or you can revert
back by setting secretRequired to false.

CVE-2019-17563

When using FORM authentication with Apache Tomcat there was a narrow
window where an attacker could perform a session fixation attack.
The window was considered too narrow for an exploit to be practical
but, erring on the side of caution, this issue has been treated as a
security vulnerability.

CVE-2020-1935

In Apache Tomcat the HTTP header parsing code used an approach to
end-of-line parsing that allowed some invalid HTTP headers to be
parsed as valid. This led to a possibility of HTTP Request Smuggling
if Tomcat was located behind a reverse proxy that incorrectly
handled the invalid Transfer-Encoding header in a particular manner.
Such a reverse proxy is considered unlikely.

CVE-2020-1938

When using the Apache JServ Protocol (AJP), care must be taken when
trusting incoming connections to Apache Tomcat. Tomcat treats AJP
connections as having higher trust than, for example, a similar HTTP
connection. If such connections are available to an attacker, they
can be exploited in ways that may be surprising. Previously Tomcat
shipped with an AJP Connector enabled by default that listened on
all configured IP addresses. It was expected (and recommended in the
security guide) that this Connector would be disabled if not
required.
.
Note that Debian already disabled the AJP connector by default.
Mitigation is only required if the AJP port was made accessible to
untrusted users.

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
attack to succeed.");

  script_tag(name:"affected", value:"'tomcat8' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
8.0.14-1+deb8u17.

We recommend that you upgrade your tomcat8 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libservlet3.1-java", ver:"8.0.14-1+deb8u17", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libservlet3.1-java-doc", ver:"8.0.14-1+deb8u17", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtomcat8-java", ver:"8.0.14-1+deb8u17", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8", ver:"8.0.14-1+deb8u17", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-admin", ver:"8.0.14-1+deb8u17", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-common", ver:"8.0.14-1+deb8u17", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-docs", ver:"8.0.14-1+deb8u17", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-examples", ver:"8.0.14-1+deb8u17", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat8-user", ver:"8.0.14-1+deb8u17", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
