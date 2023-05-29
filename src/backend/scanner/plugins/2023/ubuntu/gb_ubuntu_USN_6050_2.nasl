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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6050.2");
  script_cve_id("CVE-2023-25652", "CVE-2023-29007");
  script_tag(name:"creation_date", value:"2023-05-18 04:09:27 +0000 (Thu, 18 May 2023)");
  script_version("2023-05-19T09:09:15+0000");
  script_tag(name:"last_modification", value:"2023-05-19 09:09:15 +0000 (Fri, 19 May 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-04 21:19:00 +0000 (Thu, 04 May 2023)");

  script_name("Ubuntu: Security Advisory (USN-6050-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6050-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6050-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git' package(s) announced via the USN-6050-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6050-1 fixed several vulnerabilities in Git. This update provides
the corresponding updates for CVE-2023-25652 and CVE-2023-29007 on
Ubuntu 16.04 LTS.

Original advisory details:

 It was discovered that Git incorrectly handled certain commands.
 An attacker could possibly use this issue to overwrite paths.
 (CVE-2023-25652)

 Andre Baptista and Vitor Pinho discovered that Git incorrectly handled
 certain configurations. An attacker could possibly use this issue
 to achieve arbitrary configuration injection. (CVE-2023-29007)");

  script_tag(name:"affected", value:"'git' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"git", ver:"1:2.7.4-0ubuntu1.10+esm7", rls:"UBUNTU16.04 LTS"))) {
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
