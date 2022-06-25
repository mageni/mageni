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
  script_oid("1.3.6.1.4.1.25623.1.0.704637");
  script_version("2020-03-10T04:00:08+0000");
  script_cve_id("CVE-2020-9355");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-03-10 11:03:30 +0000 (Tue, 10 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-10 04:00:08 +0000 (Tue, 10 Mar 2020)");
  script_name("Debian: Security Advisory for network-manager-ssh (DSA-4637-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4637.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4637-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'network-manager-ssh'
  package(s) announced via the DSA-4637-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kobus van Schoor discovered that network-manager-ssh, a plugin to
provide VPN integration for SSH in NetworkManager, is prone to a
privilege escalation vulnerability. A local user with privileges to
modify a connection can take advantage of this flaw to execute arbitrary
commands as root.

This update drops support to pass extra SSH options to the ssh
invocation.");

  script_tag(name:"affected", value:"'network-manager-ssh' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), this problem has been fixed
in version 1.2.1-1+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 1.2.10-1+deb10u1.

We recommend that you upgrade your network-manager-ssh packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"network-manager-ssh", ver:"1.2.10-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"network-manager-ssh-gnome", ver:"1.2.10-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"network-manager-ssh", ver:"1.2.1-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"network-manager-ssh-gnome", ver:"1.2.1-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
