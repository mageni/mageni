###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4367.nasl 14285 2019-03-18 15:08:34Z cfischer $
#
# Auto-generated from advisory DSA 4367-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704367");
  script_version("$Revision: 14285 $");
  script_cve_id("CVE-2018-16864", "CVE-2018-16865", "CVE-2018-16866");
  script_name("Debian Security Advisory DSA 4367-1 (systemd - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 16:08:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-01-13 00:00:00 +0100 (Sun, 13 Jan 2019)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4367.html");
  script_xref(name:"URL", value:"https://www.qualys.com/2019/01/09/system-down/system-down.txt");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"systemd on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 232-25+deb9u7.

We recommend that you upgrade your systemd packages.

For the detailed security status of systemd please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/systemd");
  script_tag(name:"summary", value:"The Qualys Research Labs discovered multiple vulnerabilities in
systemd-journald. Two memory corruption flaws, via attacker-controlled
allocations using the alloca function (CVE-2018-16864,
CVE-2018-16865)
and an out-of-bounds read flaw leading to an information leak
(CVE-2018-16866),
could allow an attacker to cause a denial of service or the execution of
arbitrary code.

Further details in the Qualys Security Advisory at the linked references.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"tmpreaper", ver:"232-25+deb9u7", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-myhostname", ver:"232-25+deb9u7", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-mymachines", ver:"232-25+deb9u7", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-resolve", ver:"232-25+deb9u7", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-systemd", ver:"232-25+deb9u7", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-systemd", ver:"232-25+deb9u7", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-dev", ver:"232-25+deb9u7", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd0", ver:"232-25+deb9u7", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libudev-dev", ver:"232-25+deb9u7", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libudev1", ver:"232-25+deb9u7", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"systemd", ver:"232-25+deb9u7", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"systemd-container", ver:"232-25+deb9u7", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"systemd-coredump", ver:"232-25+deb9u7", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"systemd-journal-remote", ver:"232-25+deb9u7", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"systemd-sysv", ver:"232-25+deb9u7", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udev", ver:"232-25+deb9u7", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}