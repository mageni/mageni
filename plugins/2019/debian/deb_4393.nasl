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
  script_oid("1.3.6.1.4.1.25623.1.0.704393");
  script_version("2019-04-05T06:55:01+0000");
  script_cve_id("CVE-2019-6454");
  script_name("Debian Security Advisory DSA 4393-1 (systemd - security update)");
  script_tag(name:"last_modification", value:"2019-04-05 06:55:01 +0000 (Fri, 05 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-02-18 00:00:00 +0100 (Mon, 18 Feb 2019)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4393.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"systemd on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), this problem has been fixed in
version 232-25+deb9u9.

We recommend that you upgrade your systemd packages.

For the detailed security status of systemd please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/systemd");
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
if((res = isdpkgvuln(pkg:"libnss-myhostname", ver:"232-25+deb9u9", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-mymachines", ver:"232-25+deb9u9", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-resolve", ver:"232-25+deb9u9", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnss-systemd", ver:"232-25+deb9u9", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpam-systemd", ver:"232-25+deb9u9", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd-dev", ver:"232-25+deb9u9", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsystemd0", ver:"232-25+deb9u9", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libudev-dev", ver:"232-25+deb9u9", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libudev1", ver:"232-25+deb9u9", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"systemd", ver:"232-25+deb9u9", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"systemd-container", ver:"232-25+deb9u9", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"systemd-coredump", ver:"232-25+deb9u9", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"systemd-journal-remote", ver:"232-25+deb9u9", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"systemd-sysv", ver:"232-25+deb9u9", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"udev", ver:"232-25+deb9u9", rls:"DEB9")) != NULL) {
  report += res;
}
if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}