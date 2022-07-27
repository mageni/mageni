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
  script_oid("1.3.6.1.4.1.25623.1.0.705010");
  script_version("2021-11-17T14:03:27+0000");
  script_cve_id("CVE-2021-40690");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-11-17 14:03:27 +0000 (Wed, 17 Nov 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-01 16:08:00 +0000 (Fri, 01 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-11-17 02:00:05 +0000 (Wed, 17 Nov 2021)");
  script_name("Debian: Security Advisory for libxml-security-java (DSA-5010-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|10)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-5010.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5010-1");
  script_xref(name:"Advisory-ID", value:"DSA-5010-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml-security-java'
  package(s) announced via the DSA-5010-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Apache Santuario - XML Security for Java is vulnerable to an issue where the
secureValidation
property is not passed correctly when creating a KeyInfo
from a KeyInfoReference element. This allows an attacker to abuse an XPath
Transform to extract any local .xml files in a RetrievalMethod element.");

  script_tag(name:"affected", value:"'libxml-security-java' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (buster), this problem has been fixed
in version 2.0.10-2+deb10u1.

For the stable distribution (bullseye), this problem has been fixed in
version 2.0.10-2+deb11u1.

We recommend that you upgrade your libxml-security-java packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libxml-security-java", ver:"2.0.10-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxml-security-java-doc", ver:"2.0.10-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxml-security-java", ver:"2.0.10-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxml-security-java-doc", ver:"2.0.10-2+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
