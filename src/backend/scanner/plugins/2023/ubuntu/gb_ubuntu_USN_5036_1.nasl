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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5036.1");
  script_cve_id("CVE-2019-8955", "CVE-2021-28089", "CVE-2021-28090", "CVE-2021-34548", "CVE-2021-34549", "CVE-2021-34550", "CVE-2021-38385");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-02 02:18:00 +0000 (Thu, 02 Sep 2021)");

  script_name("Ubuntu: Security Advisory (USN-5036-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5036-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5036-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tor' package(s) announced via the USN-5036-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Tor incorrectly handled certain memory operations. A
remote attacker could use this issue to cause a denial of service. This issue
only affected Ubuntu 18.04 ESM. (CVE-2019-8955)

It was discovered that Tor did not properly handle the input length to
dump_desc() function. A remote attacker could use this issue to cause a denial
of service. This issue only affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and
Ubuntu 20.04 ESM. (CVE-2021-28089)

It was discovered that Tor did not properly sanitize the relay nickname in
dirvote_add_signatures_to_pending_consensus() function. An attacker could
possibly use this issue to cause an assertion failure and then cause a denial
of service. (CVE-2021-28090)

It was discovered that Tor did not properly validate the layer hint on
half-open streams. A remote attacker could possibly use this issue to bypass
the access control, leading to remote code execution. This issue only affected
Ubuntu 20.04 ESM. (CVE-2021-34548)

It was discovered that Tor was using an insecure hash function. A remote
attacker could use this issue to cause a denial of service. This issue only
affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and Ubuntu 20.04 ESM.
(CVE-2021-34549)

It was discovered that Tor did not properly manage memory under certain
circumstances. If a user were tricked into opening a specially crafted request,
a remote attacker could possibly use this issue to cause a crash, resulting in
a denial of service, or possibly reading sensitive data. This issue only
affected Ubuntu 18.04 ESM and Ubuntu 20.04 ESM. (CVE-2021-34550)

It was discovered that Tor mishandles the relationship between batch-signature
verification and single-signature verification. An attacker could possibly use
this issue to cause an assertion failure and then cause a denial of service.
This issue only affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and Ubuntu 20.04
ESM. (CVE-2021-38385)");

  script_tag(name:"affected", value:"'tor' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"tor", ver:"0.2.4.27-1ubuntu0.1+esm2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"tor", ver:"0.2.9.14-1ubuntu1~16.04.3+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"tor", ver:"0.3.2.10-1ubuntu0.2~esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"tor", ver:"0.4.2.7-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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
