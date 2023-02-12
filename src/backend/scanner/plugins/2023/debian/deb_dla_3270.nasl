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
  script_oid("1.3.6.1.4.1.25623.1.0.893270");
  script_version("2023-01-16T10:11:20+0000");
  script_cve_id("CVE-2022-44792", "CVE-2022-44793");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-16 10:11:20 +0000 (Mon, 16 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-16 02:00:05 +0000 (Mon, 16 Jan 2023)");
  script_name("Debian LTS: Security Advisory for net-snmp (DLA-3270-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00010.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3270-1");
  script_xref(name:"Advisory-ID", value:"DLA-3270-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1024020");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp'
  package(s) announced via the DLA-3270-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"menglong2234 discovered NULL pointer exceptions in net-snmp, a suite of
Simple Network Management Protocol applications, which could could
result in debian of service.

CVE-2022-44792

A remote attacker (with write access) could trigger a NULL
dereference while handling ipDefaultTTL via a crafted UDP packet.

CVE-2022-44793

A remote attacker (with write access) could trigger a NULL
dereference while handling ipv6IpForwarding via a crafted UDP
packet.");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
5.7.3+dfsg-5+deb10u4.

We recommend that you upgrade your net-snmp packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libsnmp-base", ver:"5.7.3+dfsg-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsnmp-dev", ver:"5.7.3+dfsg-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsnmp-perl", ver:"5.7.3+dfsg-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsnmp30", ver:"5.7.3+dfsg-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsnmp30-dbg", ver:"5.7.3+dfsg-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-netsnmp", ver:"5.7.3+dfsg-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"snmp", ver:"5.7.3+dfsg-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"snmpd", ver:"5.7.3+dfsg-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"snmptrapd", ver:"5.7.3+dfsg-5+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tkmib", ver:"5.7.3+dfsg-5+deb10u4", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
