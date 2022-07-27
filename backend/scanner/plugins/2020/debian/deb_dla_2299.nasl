# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892299");
  script_version("2020-07-31T03:00:10+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-07-31 10:00:11 +0000 (Fri, 31 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-31 03:00:10 +0000 (Fri, 31 Jul 2020)");
  script_name("Debian LTS: Security Advisory for net-snmp (DLA-2299-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00029.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2299-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/965166");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp'
  package(s) announced via the DLA-2299-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A privilege escalation vulnerability vulnerability was discovered in
Net-SNMP, a set of tools for collecting and organising information
about devices on computer networks.

Upstream notes that:

  * It is still possible to enable this MIB via the --with-mib-modules configure option.

  * Another MIB that provides similar functionality, namely
ucd-snmp/extensible, is disabled by default.

  * The security risk of ucd-snmp/pass and ucd-snmp/pass_persist is
lower since these modules only introduce a security risk if the
invoked scripts are exploitable.");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 'Stretch', this issue has been fixed in net-snmp version
5.7.3+dfsg-1.7+deb9u2.

We recommend that you upgrade your net-snmp packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libsnmp-base", ver:"5.7.3+dfsg-1.7+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsnmp-dev", ver:"5.7.3+dfsg-1.7+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsnmp-perl", ver:"5.7.3+dfsg-1.7+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsnmp30", ver:"5.7.3+dfsg-1.7+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsnmp30-dbg", ver:"5.7.3+dfsg-1.7+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-netsnmp", ver:"5.7.3+dfsg-1.7+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"snmp", ver:"5.7.3+dfsg-1.7+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"snmpd", ver:"5.7.3+dfsg-1.7+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"snmptrapd", ver:"5.7.3+dfsg-1.7+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tkmib", ver:"5.7.3+dfsg-1.7+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
