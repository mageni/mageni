# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.120");
  script_cve_id("CVE-2015-3418");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-30 02:29:00 +0000 (Tue, 30 Jan 2018)");

  script_name("Debian: Security Advisory (DLA-120)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-120");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-120-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xorg-server' package(s) announced via the DLA-120 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andreas Cord-Landwehr reported an issue where the X.Org Xserver would often crash with an arithmetic exception when maximizing application windows.

This issue (CVE-2015-3418) is a regression which got introduced by fixing CVE-2014-8092. The above referenced version of xorg-server in Debian squeeze-lts fixes this regression in the following way:

The length checking code validates PutImage height and byte width by making sure that byte-width >= INT32_MAX / height. If height is zero, this generates a divide by zero exception. Allow zero height requests explicitly, bypassing the INT32_MAX check (in dix/dispatch.c).

For Debian 6 Squeeze, these issues have been fixed in xorg-server version 2:1.7.7-18+deb6u3");

  script_tag(name:"affected", value:"'xorg-server' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"xdmx-tools", ver:"2:1.7.7-18+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xdmx", ver:"2:1.7.7-18+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xnest", ver:"2:1.7.7-18+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-common", ver:"2:1.7.7-18+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xephyr", ver:"2:1.7.7-18+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xfbdev", ver:"2:1.7.7-18+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core-dbg", ver:"2:1.7.7-18+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core-udeb", ver:"2:1.7.7-18+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.7.7-18+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-dev", ver:"2:1.7.7-18+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xvfb", ver:"2:1.7.7-18+deb6u3", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
