# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.304");
  script_cve_id("CVE-2010-3609", "CVE-2012-4428", "CVE-2015-5177");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-07 13:01:00 +0000 (Tue, 07 Nov 2017)");

  script_name("Debian: Security Advisory (DLA-304)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-304");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-304");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openslp-dfsg' package(s) announced via the DLA-304 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been found and solved in OpenSLP, that implements the Internet Engineering Task Force (IETF) Service Location Protocol standards protocol.

CVE-2010-3609

Remote attackers could cause a Denial of Service in the Service Location Protocol daemon (SLPD) via a crafted packet with a next extension offset.

CVE-2012-4428

Georgi Geshev discovered that an out-of-bounds read error in the SLPIntersectStringList() function could be used to cause a DoS.

CVE-2015-5177

A double free in the SLPDProcessMessage() function could be used to cause openslp to crash.

For Debian 6 Squeeze, these problems have been fixed in openslp-dfsg version 1.2.1-7.8+deb6u1.

We recommend that you upgrade your openslp-dfsg packages.");

  script_tag(name:"affected", value:"'openslp-dfsg' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libslp-dev", ver:"1.2.1-7.8+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslp1", ver:"1.2.1-7.8+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openslp-doc", ver:"1.2.1-7.8+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slpd", ver:"1.2.1-7.8+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slptool", ver:"1.2.1-7.8+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
