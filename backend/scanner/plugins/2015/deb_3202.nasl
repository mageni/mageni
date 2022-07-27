# OpenVAS Vulnerability Test
# $Id: deb_3202.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3202-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703202");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-2318", "CVE-2015-2319", "CVE-2015-2320");
  script_name("Debian Security Advisory DSA 3202-1 (mono - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-03-22 00:00:00 +0100 (Sun, 22 Mar 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3202.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"mono on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
these problems have been fixed in version 2.10.8.1-8+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 3.2.8+dfsg-10.

We recommend that you upgrade your mono packages.");
  script_tag(name:"summary", value:"Researchers at INRIA and Xamarin
discovered several vulnerabilities in mono, a platform for running and developing
applications based on the ECMA/ISO Standards. Mono's TLS stack contained several
problems that hampered its capabilities: those issues could lead to client
impersonation (via SKIP-TLS), SSLv2 fallback, and encryption weakening
(via FREAK).");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libmono-2.0-1", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-2.0-1-dbg", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-2.0-dev", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-accessibility2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-accessibility4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-c5-1.1-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-cairo2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-cairo4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-cecil-private-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-cil-dev", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-codecontracts4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-compilerservices-symbolwriter4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-corlib2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-corlib4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-cscompmgd8.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-csharp4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-custommarshalers4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-data-tds2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-data-tds4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-db2-1.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-debugger-soft2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-debugger-soft4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-http4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-i18n-cjk4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-i18n-mideast4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-i18n-other4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-i18n-rare4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-i18n-west2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-i18n-west4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-i18n2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-i18n4.0-all", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-i18n4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-ldap2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-ldap4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-management2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-management4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-messaging-rabbitmq2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-messaging-rabbitmq4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-messaging2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-messaging4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-microsoft-build-engine4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-microsoft-build-framework4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-microsoft-build-tasks-v4.0-4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-microsoft-build-utilities-v4.0-4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-microsoft-build2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-microsoft-csharp4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-microsoft-visualc10.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-microsoft-web-infrastructure1.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-microsoft8.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-npgsql2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-npgsql4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-opensystem-c4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-oracle2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-oracle4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-peapi2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-peapi4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-posix2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-posix4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-profiler", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-rabbitmq2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-rabbitmq4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-relaxng2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-relaxng4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-security2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-security4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-sharpzip2.6-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-sharpzip2.84-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-sharpzip4.84-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-simd2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-simd4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-sqlite2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-sqlite4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-componentmodel-composition4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-componentmodel-dataannotations4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-configuration-install4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-configuration4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-core4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-data-datasetextensions4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-data-linq2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-data-linq4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-data-services-client4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-data-services4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-data2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-data4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-design4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-drawing-design4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-drawing4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-dynamic4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-enterpriseservices4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-identitymodel-selectors4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-identitymodel4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-ldap2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-ldap4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-management4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-messaging2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-messaging4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-net4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-numerics4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-runtime-caching4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-runtime-durableinstancing4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-runtime-serialization-formatters-soap4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-runtime-serialization4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-runtime2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-runtime4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-security4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-servicemodel-discovery4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-servicemodel-routing4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-servicemodel-web4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-servicemodel4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-serviceprocess4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-transactions4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-web-abstractions4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-web-applicationservices4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-web-dynamicdata4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-web-extensions-design4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-web-extensions4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-web-mvc1.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-web-mvc2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-web-routing4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-web-services4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-web2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-web4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-windows-forms-datavisualization4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-windows-forms4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-xaml4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-xml-linq4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-xml4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-tasklets2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-tasklets4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-wcf3.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-web4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-webbrowser2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-webbrowser4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-webmatrix-data4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-windowsbase3.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-windowsbase4.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-winforms2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono2.0-cil", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-2.0-gac", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-2.0-service", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-4.0-gac", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-4.0-service", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-complete", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-csharp-shell", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-dbg", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-devel", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-dmcs", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-gac", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-gmcs", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-jay", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-mcs", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-runtime", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-runtime-dbg", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-runtime-sgen", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-utils", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-xbuild", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"monodoc-base", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"monodoc-manual", ver:"2.10.8.1-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}