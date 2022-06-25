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
  script_oid("1.3.6.1.4.1.25623.1.0.704428");
  script_version("2019-04-15T07:08:44+0000");
  script_cve_id("CVE-2019-3842");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-04-15 07:08:44 +0000 (Mon, 15 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-09 02:00:12 +0000 (Tue, 09 Apr 2019)");
  script_name("Debian Security Advisory DSA 4428-1 (systemd - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4428.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4428-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the DSA-4428-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered that the PAM module in systemd insecurely uses the
environment and lacks seat verification permitting spoofing an active
session to PolicyKit. A remote attacker with SSH access can take
advantage of this issue to gain PolicyKit privileges that are normally
only granted to clients in an active session on the local console.");

  script_tag(name:"affected", value:"'systemd' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (stretch), this problem has been fixed in
version 232-25+deb9u11.

This update includes updates previously scheduled to be released in the
stretch 9.9 point release.

We recommend that you upgrade your systemd packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libnss-myhostname", ver:"232-25+deb9u11", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnss-mymachines", ver:"232-25+deb9u11", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnss-resolve", ver:"232-25+deb9u11", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnss-systemd", ver:"232-25+deb9u11", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpam-systemd", ver:"232-25+deb9u11", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsystemd-dev", ver:"232-25+deb9u11", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsystemd0", ver:"232-25+deb9u11", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libudev-dev", ver:"232-25+deb9u11", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libudev1", ver:"232-25+deb9u11", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"systemd", ver:"232-25+deb9u11", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"systemd-container", ver:"232-25+deb9u11", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"systemd-coredump", ver:"232-25+deb9u11", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"systemd-journal-remote", ver:"232-25+deb9u11", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"systemd-sysv", ver:"232-25+deb9u11", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"udev", ver:"232-25+deb9u11", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);