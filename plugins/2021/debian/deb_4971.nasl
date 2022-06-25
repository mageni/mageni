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
  script_oid("1.3.6.1.4.1.25623.1.0.704971");
  script_version("2021-09-10T01:00:17+0000");
  script_cve_id("CVE-2021-33285", "CVE-2021-33286", "CVE-2021-33287", "CVE-2021-33289", "CVE-2021-35266", "CVE-2021-35267", "CVE-2021-35268", "CVE-2021-35269", "CVE-2021-39251", "CVE-2021-39252", "CVE-2021-39253", "CVE-2021-39254", "CVE-2021-39255", "CVE-2021-39256", "CVE-2021-39257", "CVE-2021-39258", "CVE-2021-39259", "CVE-2021-39260", "CVE-2021-39261", "CVE-2021-39262", "CVE-2021-39263");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-09-10 10:33:37 +0000 (Fri, 10 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-10 01:00:17 +0000 (Fri, 10 Sep 2021)");
  script_name("Debian: Security Advisory for ntfs-3g (DSA-4971-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4971.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4971-1");
  script_xref(name:"Advisory-ID", value:"DSA-4971-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntfs-3g'
  package(s) announced via the DSA-4971-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in NTFS-3G, a read-write NTFS
driver for FUSE. A local user can take advantage of these flaws for
local root privilege escalation.");

  script_tag(name:"affected", value:"'ntfs-3g' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (buster), these problems have been fixed
in version 1:2017.3.23AR.3-3+deb10u1.

For the stable distribution (bullseye), these problems have been fixed in
version 1:2017.3.23AR.3-4+deb11u1.

We recommend that you upgrade your ntfs-3g packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libntfs-3g883", ver:"1:2017.3.23AR.3-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g", ver:"1:2017.3.23AR.3-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g-dev", ver:"1:2017.3.23AR.3-3+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libntfs-3g883", ver:"1:2017.3.23AR.3-4+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g", ver:"1:2017.3.23AR.3-4+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g-dev", ver:"1:2017.3.23AR.3-4+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g-udeb", ver:"1:2017.3.23AR.3-4+deb11u1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
