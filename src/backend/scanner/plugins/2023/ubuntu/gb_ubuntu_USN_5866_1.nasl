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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5866.1");
  script_cve_id("CVE-2015-9543", "CVE-2017-18191", "CVE-2020-17376", "CVE-2021-3654", "CVE-2022-37394");
  script_tag(name:"creation_date", value:"2023-02-14 04:10:56 +0000 (Tue, 14 Feb 2023)");
  script_version("2023-02-14T10:18:49+0000");
  script_tag(name:"last_modification", value:"2023-02-14 10:18:49 +0000 (Tue, 14 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-14 19:00:00 +0000 (Mon, 14 Sep 2020)");

  script_name("Ubuntu: Security Advisory (USN-5866-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5866-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5866-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nova' package(s) announced via the USN-5866-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Nova did not properly manage data logged into the
log file. An attacker with read access to the service's logs could exploit
this issue and may obtain sensitive information. This issue only affected
Ubuntu 16.04 ESM and Ubuntu 18.04 LTS. (CVE-2015-9543)

It was discovered that Nova did not properly handle attaching and
reattaching the encrypted volume. An attacker could possibly use this issue
to perform a denial of service attack. This issue only affected Ubuntu
16.04 ESM. (CVE-2017-18191)

It was discovered that Nova did not properly handle the updation of domain
XML after live migration. An attacker could possibly use this issue to
corrupt the volume or perform a denial of service attack. This issue only
affected Ubuntu 18.04 LTS. (CVE-2020-17376)

It was discovered that Nova was not properly validating the URL passed to
noVNC. An attacker could possibly use this issue by providing malicious URL
to the noVNC proxy to redirect to any desired URL. This issue only affected
Ubuntu 16.04 ESM and Ubuntu 18.04 LTS. (CVE-2021-3654)

It was discovered that Nova did not properly handle changes in the neutron
port of vnic_type type. An authenticated user could possibly use this issue
to perform a denial of service attack. This issue only affected Ubuntu
20.04 LTS. (CVE-2022-37394)");

  script_tag(name:"affected", value:"'nova' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"nova-common", ver:"2:13.1.4-0ubuntu4.5+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-nova", ver:"2:13.1.4-0ubuntu4.5+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"nova-common", ver:"2:17.0.13-0ubuntu5.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-nova", ver:"2:17.0.13-0ubuntu5.3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"nova-common", ver:"2:21.2.4-0ubuntu2.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-nova", ver:"2:21.2.4-0ubuntu2.2", rls:"UBUNTU20.04 LTS"))) {
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
