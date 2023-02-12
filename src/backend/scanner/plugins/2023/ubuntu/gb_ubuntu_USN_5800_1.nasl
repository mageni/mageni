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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5800.1");
  script_cve_id("CVE-2021-44758", "CVE-2022-3437", "CVE-2022-42898", "CVE-2022-44640");
  script_tag(name:"creation_date", value:"2023-01-13 04:10:42 +0000 (Fri, 13 Jan 2023)");
  script_version("2023-01-13T10:21:10+0000");
  script_tag(name:"last_modification", value:"2023-01-13 10:21:10 +0000 (Fri, 13 Jan 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 18:28:00 +0000 (Wed, 04 Jan 2023)");

  script_name("Ubuntu: Security Advisory (USN-5800-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5800-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5800-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'heimdal' package(s) announced via the USN-5800-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Heimdal incorrectly handled certain SPNEGO tokens. A
remote attacker could possibly use this issue to cause a denial of service.
(CVE-2021-44758)

Evgeny Legerov discovered that Heimdal incorrectly handled memory when
performing certain DES decryption operations. A remote attacker could use
this issue to cause a denial of service, or possibly execute arbitrary
code. (CVE-2022-3437)

Greg Hudson discovered that Kerberos PAC implementation used in Heimdal
incorrectly handled certain parsing operations. A remote attacker could use
this issue to cause a denial of service, or possibly execute arbitrary
code. (CVE-2022-42898)

It was discovered that Heimdal's KDC did not properly handle certain error
conditions. A remote attacker could use this issue to cause a denial of
service, or possibly execute arbitrary code. (CVE-2022-44640)");

  script_tag(name:"affected", value:"'heimdal' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libasn1-8-heimdal", ver:"1.6~git20131207+dfsg-1ubuntu1.2+esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssapi3-heimdal", ver:"1.6~git20131207+dfsg-1ubuntu1.2+esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdb9-heimdal", ver:"1.6~git20131207+dfsg-1ubuntu1.2+esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhx509-5-heimdal", ver:"1.6~git20131207+dfsg-1ubuntu1.2+esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-26-heimdal", ver:"1.6~git20131207+dfsg-1ubuntu1.2+esm3", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libasn1-8-heimdal", ver:"1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssapi3-heimdal", ver:"1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdb9-heimdal", ver:"1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhx509-5-heimdal", ver:"1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-26-heimdal", ver:"1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm3", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libasn1-8-heimdal", ver:"7.5.0+dfsg-1ubuntu0.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssapi3-heimdal", ver:"7.5.0+dfsg-1ubuntu0.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdb9-heimdal", ver:"7.5.0+dfsg-1ubuntu0.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhx509-5-heimdal", ver:"7.5.0+dfsg-1ubuntu0.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-26-heimdal", ver:"7.5.0+dfsg-1ubuntu0.3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libasn1-8-heimdal", ver:"7.7.0+dfsg-1ubuntu1.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssapi3-heimdal", ver:"7.7.0+dfsg-1ubuntu1.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhdb9-heimdal", ver:"7.7.0+dfsg-1ubuntu1.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libhx509-5-heimdal", ver:"7.7.0+dfsg-1ubuntu1.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-26-heimdal", ver:"7.7.0+dfsg-1ubuntu1.3", rls:"UBUNTU20.04 LTS"))) {
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
