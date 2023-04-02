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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5961.1");
  script_cve_id("CVE-2018-10753", "CVE-2018-10771", "CVE-2019-1010069", "CVE-2021-32434", "CVE-2021-32435", "CVE-2021-32436");
  script_tag(name:"creation_date", value:"2023-03-17 04:11:07 +0000 (Fri, 17 Mar 2023)");
  script_version("2023-03-17T10:09:50+0000");
  script_tag(name:"last_modification", value:"2023-03-17 10:09:50 +0000 (Fri, 17 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 22:08:00 +0000 (Mon, 28 Nov 2022)");

  script_name("Ubuntu: Security Advisory (USN-5961-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5961-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5961-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'abcm2ps' package(s) announced via the USN-5961-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that abcm2ps incorrectly
handled memory when parsing specially crafted ABC files.
An attacker could use this issue to cause abcm2ps to crash,
leading to a denial of service, or possibly execute
arbitrary code. This issue only affected Ubuntu 16.04 ESM
and Ubuntu 18.04 LTS.
(CVE-2018-10753, CVE-2018-10771, CVE-2019-1010069)

Chiba of Topsec Alpha Lab discovered that abcm2ps incorrectly
handled memory when parsing specially crafted ABC files.
An attacker could use this issue to cause abcm2ps to crash,
leading to a denial of service.
(CVE-2021-32434, CVE-2021-32435, CVE-2021-32436)");

  script_tag(name:"affected", value:"'abcm2ps' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"abcm2ps", ver:"7.8.9-1ubuntu0.16.04.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"abcm2ps", ver:"7.8.9-1+deb9u1build0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"abcm2ps", ver:"8.14.6-0.1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"abcm2ps", ver:"8.14.11-0.1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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
