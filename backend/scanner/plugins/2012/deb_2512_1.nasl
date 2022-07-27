# OpenVAS Vulnerability Test
# $Id: deb_2512_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2512-1 (mono)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.71488");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2012-3382");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-08-10 03:12:04 -0400 (Fri, 10 Aug 2012)");
  script_name("Debian Security Advisory DSA 2512-1 (mono)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202512-1");
  script_tag(name:"insight", value:"Marcus Meissner discovered that the web server included in Mono performed
insufficient sanitising of requests, resulting in cross-site scripting.

For the stable distribution (squeeze), this problem has been fixed in
version 2.6.7-5.1.

For the unstable distribution (sid), this problem has been fixed in
version 2.10.8.1-5.");

  script_tag(name:"solution", value:"We recommend that you upgrade your mono packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to mono
announced via advisory DSA 2512-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libmono-accessibility1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-accessibility2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-bytefx0.7.6.1-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-bytefx0.7.6.2-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-c5-1.1-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-cairo1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-cairo2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-cecil-private-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-cil-dev", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-corlib1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-corlib2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-cscompmgd7.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-cscompmgd8.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-data-tds1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-data-tds2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-data1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-data2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-db2-1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-debugger-soft0.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-dev", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-firebirdsql1.7-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-getoptions1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-getoptions2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-i18n-west1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-i18n-west2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-i18n1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-i18n2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-ldap1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-ldap2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-management2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-messaging-rabbitmq2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-messaging2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-microsoft-build2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-microsoft7.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-microsoft8.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-npgsql1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-npgsql2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-oracle1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-oracle2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-peapi1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-peapi2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-posix1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-posix2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-profiler", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-rabbitmq2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-relaxng1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-relaxng2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-security1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-security2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-sharpzip0.6-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-sharpzip0.84-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-sharpzip2.6-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-sharpzip2.84-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-simd2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-sqlite1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-sqlite2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-data-linq2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-data1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-data2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-ldap1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-ldap2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-messaging1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-messaging2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-runtime1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-runtime2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-web-mvc1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-web-mvc2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-web1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system-web2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-system2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-tasklets2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-wcf3.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-webbrowser0.5-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-windowsbase3.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-winforms1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono-winforms2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono0", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono0-dbg", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono1.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmono2.0-cil", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-1.0-devel", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-1.0-gac", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-1.0-service", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-2.0-devel", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-2.0-gac", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-2.0-service", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-complete", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-csharp-shell", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-dbg", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-devel", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-gac", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-gmcs", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-jay", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-mcs", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-mjs", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-runtime", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-runtime-dbg", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-utils", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mono-xbuild", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"monodoc-base", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"monodoc-manual", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"prj2make-sharp", ver:"2.6.7-5.1", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}