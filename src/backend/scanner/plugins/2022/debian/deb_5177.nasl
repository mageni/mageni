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
  script_oid("1.3.6.1.4.1.25623.1.0.705177");
  script_version("2022-07-08T06:04:19+0000");
  script_cve_id("CVE-2022-24851", "CVE-2022-31084", "CVE-2022-31085", "CVE-2022-31086", "CVE-2022-31087", "CVE-2022-31088");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-07-08 06:04:19 +0000 (Fri, 08 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-25 17:55:00 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-07-07 01:00:10 +0000 (Thu, 07 Jul 2022)");
  script_name("Debian: Security Advisory for ldap-account-manager (DSA-5177-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5177.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5177-1");
  script_xref(name:"Advisory-ID", value:"DSA-5177-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ldap-account-manager'
  package(s) announced via the DSA-5177-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Arseniy Sharoglazov discovered multiple security issues in LDAP Account
Manager (LAM), a web frontend for managing accounts in an LDAP directory,
which could result in information disclosure or unauthenticated remote
code execution.");

  script_tag(name:"affected", value:"'ldap-account-manager' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), these problems have been fixed in
version 8.0.1-0+deb11u1.

We recommend that you upgrade your ldap-account-manager packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ldap-account-manager", ver:"8.0.1-0+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ldap-account-manager-lamdaemon", ver:"8.0.1-0+deb11u1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
