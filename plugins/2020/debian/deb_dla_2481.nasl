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
  script_oid("1.3.6.1.4.1.25623.1.0.892481");
  script_version("2020-12-05T04:00:21+0000");
  script_cve_id("CVE-2020-25709", "CVE-2020-25710");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-12-07 11:03:21 +0000 (Mon, 07 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-05 04:00:21 +0000 (Sat, 05 Dec 2020)");
  script_name("Debian LTS: Security Advisory for openldap (DLA-2481-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00008.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2481-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap'
  package(s) announced via the DLA-2481-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities in the certificate list syntax verification and
in the handling of CSN normalization were discovered in OpenLDAP, a
free implementation of the Lightweight Directory Access Protocol.
An unauthenticated remote attacker can take advantage of these
flaws to cause a denial of service (slapd daemon crash) via
specially crafted packets.");

  script_tag(name:"affected", value:"'openldap' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.4.44+dfsg-5+deb9u6.

We recommend that you upgrade your openldap packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ldap-utils", ver:"2.4.44+dfsg-5+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libldap-2.4-2", ver:"2.4.44+dfsg-5+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libldap-2.4-2-dbg", ver:"2.4.44+dfsg-5+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libldap-common", ver:"2.4.44+dfsg-5+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libldap2-dev", ver:"2.4.44+dfsg-5+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slapd", ver:"2.4.44+dfsg-5+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slapd-dbg", ver:"2.4.44+dfsg-5+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"slapd-smbk5pwd", ver:"2.4.44+dfsg-5+deb9u6", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
