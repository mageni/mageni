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
  script_oid("1.3.6.1.4.1.25623.1.0.892215");
  script_version("2020-05-20T03:00:08+0000");
  script_cve_id("CVE-2020-3327", "CVE-2020-3341");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-05-26 09:19:23 +0000 (Tue, 26 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-20 03:00:08 +0000 (Wed, 20 May 2020)");
  script_name("Debian LTS: Security Advisory for clamav (DLA-2215-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/05/msg00018.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2215-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav'
  package(s) announced via the DLA-2215-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following CVE(s) were found in src:clamav package.

CVE-2020-3327

A vulnerability in the ARJ archive parsing module in Clam
AntiVirus (ClamAV) could allow an unauthenticated, remote
attacker to cause a denial of service condition on an affected
device. The vulnerability is due to a heap buffer overflow read.
An attacker could exploit this vulnerability by sending a crafted
ARJ file to an affected device. An exploit could allow the
attacker to cause the ClamAV scanning process crash, resulting
in a denial of service condition.

CVE-2020-3341

A vulnerability in the PDF archive parsing module in Clam
AntiVirus (ClamAV) could allow an unauthenticated, remote
attacker to cause a denial of service condition on an affected
device. The vulnerability is due to a stack buffer overflow read.
An attacker could exploit this vulnerability by sending a crafted
PDF file to an affected device. An exploit could allow the
attacker to cause the ClamAV scanning process crash, resulting
in a denial of service condition.");

  script_tag(name:"affected", value:"'clamav' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
0.101.5+dfsg-0+deb8u2.

We recommend that you upgrade your clamav packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"clamav", ver:"0.101.5+dfsg-0+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clamav-base", ver:"0.101.5+dfsg-0+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.101.5+dfsg-0+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clamav-dbg", ver:"0.101.5+dfsg-0+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clamav-docs", ver:"0.101.5+dfsg-0+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clamav-freshclam", ver:"0.101.5+dfsg-0+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clamav-milter", ver:"0.101.5+dfsg-0+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clamav-testfiles", ver:"0.101.5+dfsg-0+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clamdscan", ver:"0.101.5+dfsg-0+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libclamav-dev", ver:"0.101.5+dfsg-0+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libclamav7", ver:"0.101.5+dfsg-0+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libclamav9", ver:"0.101.5+dfsg-0+deb8u2", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
