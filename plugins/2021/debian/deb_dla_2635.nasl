# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892635");
  script_version("2021-04-26T08:46:56+0000");
  script_cve_id("CVE-2018-11039", "CVE-2018-11040", "CVE-2018-1270", "CVE-2018-15756");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-26 10:09:32 +0000 (Mon, 26 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-24 03:02:23 +0000 (Sat, 24 Apr 2021)");
  script_name("Debian LTS: Security Advisory for libspring-java (DLA-2635-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00022.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2635-1");
  script_xref(name:"Advisory-ID", value:"DLA-2635-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/895114");
  script_xref(name:"URL", value:"https://bugs.debian.org/911786");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libspring-java'
  package(s) announced via the DLA-2635-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in libspring-java, a modular
Java/J2EE application framework. An attacker may execute code, perform
XST attack, issue unauthorized cross-domain requests or cause a DoS
(Denial-of-Service) in specific configurations.

CVE-2018-1270

Spring Framework allows applications to expose STOMP over
WebSocket endpoints with a simple, in-memory STOMP broker through
the spring-messaging module. A malicious user (or attacker) can
craft a message to the broker that can lead to a remote code
execution attack.

CVE-2018-11039

Spring Framework allows web applications to change the HTTP
request method to any HTTP method (including TRACE) using the
HiddenHttpMethodFilter in Spring MVC. If an application has a
pre-existing XSS vulnerability, a malicious user (or attacker) can
use this filter to escalate to an XST (Cross Site Tracing) attack.

CVE-2018-11040

Spring Framework allows web applications to enable cross-domain
requests via JSONP (JSON with Padding) through
AbstractJsonpResponseBodyAdvice for REST controllers and
MappingJackson2JsonView for browser requests. Both are not enabled
by default in Spring Framework nor Spring Boot, however, when
MappingJackson2JsonView is configured in an application, JSONP
support is automatically ready to use through the 'jsonp' and
'callback' JSONP parameters, enabling cross-domain requests.

CVE-2018-15756

Spring Framework provides support for range requests when serving
static resources through the ResourceHttpRequestHandler, or
starting in 5.0 when an annotated controller returns an
org.springframework.core.io.Resource. A malicious user (or
attacker) can add a range header with a high number of ranges, or
with wide ranges that overlap, or both, for a denial of service
attack.");

  script_tag(name:"affected", value:"'libspring-java' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
4.3.5-1+deb9u1.

We recommend that you upgrade your libspring-java packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libspring-aop-java", ver:"4.3.5-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-beans-java", ver:"4.3.5-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-context-java", ver:"4.3.5-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-context-support-java", ver:"4.3.5-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-core-java", ver:"4.3.5-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-expression-java", ver:"4.3.5-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-instrument-java", ver:"4.3.5-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-jdbc-java", ver:"4.3.5-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-jms-java", ver:"4.3.5-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-messaging-java", ver:"4.3.5-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-orm-java", ver:"4.3.5-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-oxm-java", ver:"4.3.5-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-test-java", ver:"4.3.5-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-transaction-java", ver:"4.3.5-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-web-java", ver:"4.3.5-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-web-portlet-java", ver:"4.3.5-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-web-servlet-java", ver:"4.3.5-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
