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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6049.1");
  script_cve_id("CVE-2020-11612", "CVE-2021-21290", "CVE-2021-21295", "CVE-2021-21409", "CVE-2021-37136", "CVE-2021-37137", "CVE-2021-43797", "CVE-2022-41881", "CVE-2022-41915");
  script_tag(name:"creation_date", value:"2023-05-01 04:09:46 +0000 (Mon, 01 May 2023)");
  script_version("2023-05-04T09:51:03+0000");
  script_tag(name:"last_modification", value:"2023-05-04 09:51:03 +0000 (Thu, 04 May 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-19 16:55:00 +0000 (Mon, 19 Dec 2022)");

  script_name("Ubuntu: Security Advisory (USN-6049-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6049-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6049-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netty' package(s) announced via the USN-6049-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Netty's Zlib decoders did not limit memory
allocations. A remote attacker could possibly use this issue to cause
Netty to exhaust memory via malicious input, leading to a denial of
service. This issue only affected Ubuntu 16.04 ESM and Ubuntu 20.04 ESM.
(CVE-2020-11612)

It was discovered that Netty created temporary files with excessive
permissions. A local attacker could possibly use this issue to expose
sensitive information. This issue only affected Ubuntu 16.04 ESM, Ubuntu
18.04 ESM, and Ubuntu 20.04 ESM. (CVE-2021-21290)

It was discovered that Netty did not properly validate content-length
headers. A remote attacker could possibly use this issue to smuggle
requests. This issue was only fixed in Ubuntu 20.04 ESM. (CVE-2021-21295,
CVE-2021-21409)

It was discovered that Netty's Bzip2 decompression decoder did not limit
the decompressed output data size. A remote attacker could possibly use
this issue to cause Netty to exhaust memory via malicious input, leading
to a denial of service. This issue only affected Ubuntu 18.04 ESM, Ubuntu
20.04 ESM, Ubuntu 22.04 LTS, and Ubuntu 22.10. (CVE-2021-37136)

It was discovered that Netty's Snappy frame decoder function did not limit
chunk lengths. A remote attacker could possibly use this issue to cause
Netty to exhaust memory via malicious input, leading to a denial of
service. (CVE-2021-37137)

It was discovered that Netty did not properly handle control chars at the
beginning and end of header names. A remote attacker could possibly use
this issue to smuggle requests. This issue only affected Ubuntu 18.04 ESM,
Ubuntu 20.04 ESM, Ubuntu 22.04 LTS, and Ubuntu 22.10. (CVE-2021-43797)

It was discovered that Netty could be made into an infinite recursion when
parsing a malformed crafted message. A remote attacker could possibly use
this issue to cause Netty to crash, leading to a denial of service. This
issue only affected Ubuntu 20.04 ESM, Ubuntu 22.04 LTS, and Ubuntu 22.10.
(CVE-2022-41881)

It was discovered that Netty did not validate header values under certain
circumstances. A remote attacker could possibly use this issue to perform
HTTP response splitting via malicious header values. This issue only
affected Ubuntu 18.04 ESM, Ubuntu 20.04 ESM, Ubuntu 22.04 LTS, and Ubuntu
22.10. (CVE-2022-41915)");

  script_tag(name:"affected", value:"'netty' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 22.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libnetty-java", ver:"1:4.0.34-1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libnetty-java", ver:"1:4.1.7-4ubuntu0.1+esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libnetty-java", ver:"1:4.1.45-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libnetty-java", ver:"1:4.1.48-4+deb11u1build0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libnetty-java", ver:"1:4.1.48-5ubuntu0.1", rls:"UBUNTU22.10"))) {
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
