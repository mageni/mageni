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
  script_oid("1.3.6.1.4.1.25623.1.0.891684");
  script_version("2019-04-05T06:55:01+0000");
  script_cve_id("CVE-2019-6454");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1684-1] systemd security update)");
  script_tag(name:"last_modification", value:"2019-04-05 06:55:01 +0000 (Fri, 05 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-02-20 00:00:00 +0100 (Wed, 20 Feb 2019)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/02/msg00031.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"systemd on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
215-17+deb8u10.

We recommend that you upgrade your systemd packages.");
  script_tag(name:"summary", value:"Chris Coulson discovered a flaw in systemd leading to denial of service.
An unprivileged user could take advantage of this issue to crash PID1 by
sending a specially crafted D-Bus message on the system bus.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"gir1.2-gudev-1.0", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgudev-1.0-0", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgudev-1.0-dev", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-systemd", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-daemon-dev", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-daemon0", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-dev", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-id128-0", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-id128-dev", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-journal-dev", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-journal0", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-login-dev", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-login0", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd0", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libudev-dev", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libudev1", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python3-systemd", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"systemd", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"systemd-dbg", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"systemd-sysv", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udev", ver:"215-17+deb8u10", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}