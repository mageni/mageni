###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1639.nasl 14282 2019-03-18 14:55:18Z cfischer $
#
# Auto-generated from advisory DLA 1639-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891639");
  script_version("$Revision: 14282 $");
  script_cve_id("CVE-2018-16864", "CVE-2018-16865");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1639-1] systemd security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:55:18 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-01-23 00:00:00 +0100 (Wed, 23 Jan 2019)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/01/msg00016.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2019 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"systemd on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
215-17+deb8u9.

We recommend that you upgrade your systemd packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities were found in the journald component of
systemd which can lead to a crash or code execution.

CVE-2018-16864

An allocation of memory without limits, that could result in the
stack clashing with another memory region, was discovered in
systemd-journald when many entries are sent to the journal
socket. A local attacker, or a remote one if
systemd-journal-remote is used, may use this flaw to crash
systemd-journald or execute code with journald privileges.

CVE-2018-16865

An allocation of memory without limits, that could result in the
stack clashing with another memory region, was discovered in
systemd-journald when a program with long command line arguments
calls syslog. A local attacker may use this flaw to crash
systemd-journald or escalate his privileges. Versions through v240
are vulnerable.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"gir1.2-gudev-1.0", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgudev-1.0-0", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgudev-1.0-dev", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-systemd", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-daemon-dev", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-daemon0", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-dev", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-id128-0", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-id128-dev", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-journal-dev", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-journal0", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-login-dev", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-login0", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd0", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libudev-dev", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libudev1", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python3-systemd", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"systemd", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"systemd-dbg", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"systemd-sysv", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udev", ver:"215-17+deb8u9", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}