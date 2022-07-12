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
  script_oid("1.3.6.1.4.1.25623.1.0.704818");
  script_version("2020-12-28T10:19:07+0000");
  script_cve_id("CVE-2020-10936", "CVE-2020-26880", "CVE-2020-26932", "CVE-2020-29668", "CVE-2020-9369");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-12-28 11:32:25 +0000 (Mon, 28 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-25 04:00:11 +0000 (Fri, 25 Dec 2020)");
  script_name("Debian: Security Advisory for sympa (DSA-4818-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4818.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4818-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sympa'
  package(s) announced via the DSA-4818-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Sympa, a mailing list
manager, which could result in local privilege escalation, denial of
service or unauthorized access via the SOAP API.

Additionally to mitigate CVE-2020-26880 the sympa_newaliases-wrapper is no longer installed
setuid root by default. A new Debconf question is introduced to allow
setuid installations in setups where it is needed.");

  script_tag(name:"affected", value:"'sympa' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 6.2.40~dfsg-1+deb10u1.

We recommend that you upgrade your sympa packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"sympa", ver:"6.2.40~dfsg-1+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
