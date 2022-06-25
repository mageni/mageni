# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.705011");
  script_version("2021-11-20T02:00:19+0000");
  script_cve_id("CVE-2020-28243", "CVE-2020-28972", "CVE-2020-35662", "CVE-2021-21996", "CVE-2021-25281", "CVE-2021-25282", "CVE-2021-25283", "CVE-2021-25284", "CVE-2021-3144", "CVE-2021-3148", "CVE-2021-31607", "CVE-2021-3197");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-11-20 02:00:19 +0000 (Sat, 20 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-20 02:00:19 +0000 (Sat, 20 Nov 2021)");
  script_name("Debian: Security Advisory for salt (DSA-5011-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-5011.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5011-1");
  script_xref(name:"Advisory-ID", value:"DSA-5011-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt'
  package(s) announced via the DSA-5011-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been discovered in Salt, a powerful
remote execution manager, that allow for local privilege escalation on a
minion, server side template injection attacks, insufficient checks for eauth
credentials, shell and command injections or incorrect validation of SSL
certificates.");

  script_tag(name:"affected", value:"'salt' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (buster), this problem has been fixed
in version 2018.3.4+dfsg1-6+deb10u3.

For the stable distribution (bullseye), this problem has been fixed in
version 3002.6+dfsg1-4+deb11u1.

We recommend that you upgrade your salt packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"salt-api", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-cloud", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-common", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-doc", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-master", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-minion", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-proxy", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-ssh", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-syndic", ver:"2018.3.4+dfsg1-6+deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-api", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-cloud", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-common", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-doc", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-master", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-minion", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-proxy", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-ssh", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-syndic", ver:"3002.6+dfsg1-4+deb11u1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
