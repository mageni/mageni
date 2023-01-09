# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.893250");
  script_version("2023-01-02T10:12:16+0000");
  script_cve_id("CVE-2022-41973", "CVE-2022-41974");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-02 10:12:16 +0000 (Mon, 02 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-12-30 02:00:09 +0000 (Fri, 30 Dec 2022)");
  script_name("Debian LTS: Security Advisory for multipath-tools (DLA-3250-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/12/msg00037.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3250-1");
  script_xref(name:"Advisory-ID", value:"DLA-3250-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1022742");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'multipath-tools'
  package(s) announced via the DLA-3250-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues were found in multipath-tools, a tool-chain to manage disk
multipath device maps, which may be used by local attackers to obtain root
privileges or create a directories or overwrite files via symlink attacks.

Please note that the fix for CVE-2022-41973 involves switching from
/dev/shm to systemd-tmpfiles (/run/multipath-tools).
If you have previously accesssed /dev/shm directly, please update your
setup to the new path to facilitate this change.

CVE-2022-41973

multipath-tools 0.7.7 through 0.9.x before 0.9.2 allows local users to
obtain root access, as exploited in conjunction with CVE-2022-41974.
Local users able to access /dev/shm can change symlinks in multipathd
due to incorrect symlink handling, which could lead to controlled file
writes outside of the /dev/shm directory. This could be used indirectly
for local privilege escalation to root.

CVE-2022-41974

multipath-tools 0.7.0 through 0.9.x before 0.9.2 allows local users to
obtain root access, as exploited alone or in conjunction with
CVE-2022-41973. Local users able to write to UNIX domain sockets can
bypass access controls and manipulate the multipath setup. This can lead
to local privilege escalation to root. This occurs because an attacker
can repeat a keyword, which is mishandled because arithmetic ADD is used
instead of bitwise OR.");

  script_tag(name:"affected", value:"'multipath-tools' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
0.7.9-3+deb10u2.

We recommend that you upgrade your multipath-tools packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"kpartx", ver:"0.7.9-3+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-tools", ver:"0.7.9-3+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"multipath-tools-boot", ver:"0.7.9-3+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
