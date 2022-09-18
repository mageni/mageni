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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5463.2");
  script_cve_id("CVE-2022-30783", "CVE-2022-30784", "CVE-2022-30785", "CVE-2022-30786", "CVE-2022-30787", "CVE-2022-30788", "CVE-2022-30789");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-08 03:05:00 +0000 (Wed, 08 Jun 2022)");

  script_name("Ubuntu: Security Advisory (USN-5463-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5463-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5463-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntfs-3g' package(s) announced via the USN-5463-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5463-1 fixed vulnerabilities in NTFS-3G. This update provides the
corresponding updates for Ubuntu 14.04 ESM and Ubuntu 16.04 ESM.

Original advisory details:

 Roman Fiedler discovered that NTFS-3G incorrectly handled certain return
 codes. A local attacker could possibly use this issue to intercept
 protocol traffic between FUSE and the kernel. (CVE-2022-30783)

 It was discovered that NTFS-3G incorrectly handled certain NTFS disk
 images. If a user or automated system were tricked into mounting a
 specially crafted disk image, a remote attacker could use this issue to
 cause a denial of service, or possibly execute arbitrary code.
 (CVE-2022-30784, CVE-2022-30786, CVE-2022-30788, CVE-2022-30789)

 Roman Fiedler discovered that NTFS-3G incorrectly handled certain file
 handles. A local attacker could possibly use this issue to read and write
 arbitrary memory. (CVE-2022-30785, CVE-2022-30787)");

  script_tag(name:"affected", value:"'ntfs-3g' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g", ver:"1:2013.1.13AR.1-2ubuntu2+esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g", ver:"1:2015.3.14AR.1-1ubuntu0.3+esm3", rls:"UBUNTU16.04 LTS"))) {
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
