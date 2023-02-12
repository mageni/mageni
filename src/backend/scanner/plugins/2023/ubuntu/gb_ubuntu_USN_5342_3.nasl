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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5342.3");
  script_cve_id("CVE-2021-3426", "CVE-2021-4189", "CVE-2022-0391");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-17 22:17:00 +0000 (Thu, 17 Feb 2022)");

  script_name("Ubuntu: Security Advisory (USN-5342-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5342-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5342-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.7' package(s) announced via the USN-5342-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5342-1 fixed several vulnerabilities in Python. This update provides
the corresponding fix for CVE-2021-3426 for Ubuntu 18.04 ESM.

Original advisory details:

 David Schworer discovered that Python incorrectly handled certain inputs.
 An attacker could possibly use this issue to expose sensitive information.
 This issue only affected Ubuntu 18.04 LTS. (CVE-2021-3426)

 It was discovered that Python incorrectly handled certain FTP requests.
 An attacker could possibly use this issue to expose sensitive information.
 This issue only affected Ubuntu 14.04 ESM, Ubuntu 16.04 ESM, and Ubuntu 18.04 LTS.
 (CVE-2021-4189)

 It was discovered that Python incorrectly handled certain inputs.
 An attacker could possibly use this issue to execute arbitrary code.
 (CVE-2022-0391)");

  script_tag(name:"affected", value:"'python3.7' package(s) on Ubuntu 18.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python3.7-minimal", ver:"3.7.5-2ubuntu1~18.04.2+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.7", ver:"3.7.5-2ubuntu1~18.04.2+esm1", rls:"UBUNTU18.04 LTS"))) {
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
