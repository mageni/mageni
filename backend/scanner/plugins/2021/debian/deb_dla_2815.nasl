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
  script_oid("1.3.6.1.4.1.25623.1.0.892815");
  script_version("2021-11-15T09:54:42+0000");
  script_cve_id("CVE-2020-28243", "CVE-2020-28972", "CVE-2020-35662", "CVE-2021-25281", "CVE-2021-25282", "CVE-2021-25283", "CVE-2021-25284", "CVE-2021-3144", "CVE-2021-3148", "CVE-2021-31607", "CVE-2021-3197");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-01 17:15:00 +0000 (Thu, 01 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-11-11 02:00:16 +0000 (Thu, 11 Nov 2021)");
  script_name("Debian LTS: Security Advisory for salt (DLA-2815-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/11/msg00009.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2815-1");
  script_xref(name:"Advisory-ID", value:"DLA-2815-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/987496");
  script_xref(name:"URL", value:"https://bugs.debian.org/987496");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt'
  package(s) announced via the DLA-2815-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been discovered in Salt, a powerful
remote execution manager, that allow for local privilege escalation on a
minion, server side template injection attacks, insufficient checks for
eauth credentials, shell and command injections or incorrect validation of
SSL certificates.");

  script_tag(name:"affected", value:"'salt' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2016.11.2+ds-1+deb9u7.

We recommend that you upgrade your salt packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"salt-api", ver:"2016.11.2+ds-1+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-cloud", ver:"2016.11.2+ds-1+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-common", ver:"2016.11.2+ds-1+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-doc", ver:"2016.11.2+ds-1+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-master", ver:"2016.11.2+ds-1+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-minion", ver:"2016.11.2+ds-1+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-proxy", ver:"2016.11.2+ds-1+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-ssh", ver:"2016.11.2+ds-1+deb9u7", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"salt-syndic", ver:"2016.11.2+ds-1+deb9u7", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
