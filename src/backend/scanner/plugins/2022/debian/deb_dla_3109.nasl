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
  script_oid("1.3.6.1.4.1.25623.1.0.893109");
  script_version("2022-09-16T01:00:07+0000");
  script_cve_id("CVE-2019-14433");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-16 01:00:07 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-16 01:00:07 +0000 (Fri, 16 Sep 2022)");
  script_name("Debian LTS: Security Advisory for nova (DLA-3109-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/09/msg00018.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3109-1");
  script_xref(name:"Advisory-ID", value:"DLA-3109-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/934114");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nova'
  package(s) announced via the DLA-3109-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that authenticated users could trigger a fault in Nova, a
cloud computing fabric controller, to cause information leak.

In addition, this update includes some fixes for volume live migration,
as well as the addition of a /healthcheck URL for monitoring.");

  script_tag(name:"affected", value:"'nova' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, this problem has been fixed in version
2:18.1.0-6+deb10u1.

We recommend that you upgrade your nova packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"nova-api", ver:"2:18.1.0-6+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nova-cells", ver:"2:18.1.0-6+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nova-common", ver:"2:18.1.0-6+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nova-compute", ver:"2:18.1.0-6+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nova-compute-ironic", ver:"2:18.1.0-6+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nova-compute-kvm", ver:"2:18.1.0-6+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nova-compute-lxc", ver:"2:18.1.0-6+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nova-compute-qemu", ver:"2:18.1.0-6+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nova-conductor", ver:"2:18.1.0-6+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nova-console", ver:"2:18.1.0-6+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nova-consoleauth", ver:"2:18.1.0-6+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nova-consoleproxy", ver:"2:18.1.0-6+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nova-doc", ver:"2:18.1.0-6+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nova-placement-api", ver:"2:18.1.0-6+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nova-scheduler", ver:"2:18.1.0-6+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nova-volume", ver:"2:18.1.0-6+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-nova", ver:"2:18.1.0-6+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
