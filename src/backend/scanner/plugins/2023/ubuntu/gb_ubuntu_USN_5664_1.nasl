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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5664.1");
  script_cve_id("CVE-2016-10506", "CVE-2016-7445", "CVE-2016-9112", "CVE-2017-17479", "CVE-2018-18088", "CVE-2020-27824");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-29 14:51:00 +0000 (Thu, 29 Nov 2018)");

  script_name("Ubuntu: Security Advisory (USN-5664-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5664-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5664-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg' package(s) announced via the USN-5664-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenJPEG did not properly handle PNM
headers, resulting in a null pointer dereference. A remote
attacker could possibly use this issue to cause a denial of
service (DoS). (CVE-2016-7445)

It was discovered that OpenJPEG incorrectly handled certain
image files resulting in division by zero. A remote attacker
could possibly use this issue to cause a denial of service
(DoS). (CVE-2016-9112 and CVE-2016-10506)

It was discovered that OpenJPEG incorrectly handled converting
certain image files resulting in a stack buffer overflow. A
remote attacker could possibly use this issue to cause a
denial of service (DoS). (CVE-2017-17479)

It was discovered that OpenJPEG incorrectly handled converting
PNM image files resulting in a null pointer dereference. A
remote attacker could possibly use this issue to cause a denial
of service (DoS). (CVE-2018-18088)

It was discovered that OpenJPEG incorrectly handled converting
DWT images files resulting in a buffer overflow. A remote
attacker could possibly use this issue to cause a denial of
service (DoS). (CVE-2020-27824)");

  script_tag(name:"affected", value:"'openjpeg' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openjpeg-tools", ver:"1:1.5.2-3.1ubuntu0.1~esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjpip-dec-server", ver:"1:1.5.2-3.1ubuntu0.1~esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjpip-server", ver:"1:1.5.2-3.1ubuntu0.1~esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjpip-viewer-xerces", ver:"1:1.5.2-3.1ubuntu0.1~esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjpip-viewer", ver:"1:1.5.2-3.1ubuntu0.1~esm2", rls:"UBUNTU16.04 LTS"))) {
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
