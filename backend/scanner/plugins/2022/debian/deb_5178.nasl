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
  script_oid("1.3.6.1.4.1.25623.1.0.705178");
  script_version("2022-07-08T01:00:15+0000");
  script_cve_id("CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21127", "CVE-2022-21151", "CVE-2022-21166");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-07-08 01:00:15 +0000 (Fri, 08 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-08 01:00:15 +0000 (Fri, 08 Jul 2022)");
  script_name("Debian: Security Advisory for intel-microcode (DSA-5178-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5178.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5178-1");
  script_xref(name:"Advisory-ID", value:"DSA-5178-1");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/processor-mmio-stale-data-vulnerabilities.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'intel-microcode'
  package(s) announced via the DSA-5178-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update ships updated CPU microcode for some types of Intel CPUs and
provides mitigations for security vulnerabilities.

CVE-2022-21123,
CVE-2022-21125,
CVE-2022-21127,
CVE-2022-21166
Various researchers discovered flaws in Intel processors,
collectively referred to as MMIO Stale Data vulnerabilities, which
may result in information leak to local users.

For details please refer to
[link moved to references]

CVE-2022-21151
Alysa Milburn, Jason Brandt, Avishai Redelman and Nir Lavi
discovered that for some Intel processors optimization removal or
modification of security-critical code may result in information
disclosure to local users.");

  script_tag(name:"affected", value:"'intel-microcode' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (buster), these problems have been fixed
in version 3.20220510.1~deb10u1.

For the stable distribution (bullseye), these problems have been fixed in
version 3.20220510.1~deb11u1.

We recommend that you upgrade your intel-microcode packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20220510.1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20220510.1~deb11u1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
