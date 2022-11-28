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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5734.1");
  script_cve_id("CVE-2022-39282", "CVE-2022-39283", "CVE-2022-39316", "CVE-2022-39317", "CVE-2022-39318", "CVE-2022-39319", "CVE-2022-39320", "CVE-2022-39347");
  script_tag(name:"creation_date", value:"2022-11-23 04:10:36 +0000 (Wed, 23 Nov 2022)");
  script_version("2022-11-23T04:10:36+0000");
  script_tag(name:"last_modification", value:"2022-11-23 04:10:36 +0000 (Wed, 23 Nov 2022)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-18 18:57:00 +0000 (Fri, 18 Nov 2022)");

  script_name("Ubuntu: Security Advisory (USN-5734-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5734-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5734-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp2' package(s) announced via the USN-5734-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FreeRDP incorrectly handled certain data lenghts. A
malicious server could use this issue to cause FreeRDP clients to crash,
resulting in a denial of service, or possibly obtain sensitive information.
This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu
22.04 LTS. (CVE-2022-39282, CVE-2022-39283)

It was discovered that FreeRDP incorrectly handled certain data lenghts. A
malicious server could use this issue to cause FreeRDP clients to crash,
resulting in a denial of service, or possibly obtain sensitive information.
(CVE-2022-39316, CVE-2022-39317, CVE-2022-39318, CVE-2022-39319,
CVE-2022-39320)

It was discovered that FreeRDP incorrectly handled certain path checks. A
malicious server could use this issue to cause FreeRDP clients to read
files outside of the shared directory. (CVE-2022-39347)");

  script_tag(name:"affected", value:"'freerdp2' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 22.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client2-2", ver:"2.2.0+dfsg1-0ubuntu0.18.04.4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-server2-2", ver:"2.2.0+dfsg1-0ubuntu0.18.04.4", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client2-2", ver:"2.2.0+dfsg1-0ubuntu0.20.04.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-server2-2", ver:"2.2.0+dfsg1-0ubuntu0.20.04.4", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client2-2", ver:"2.6.1+dfsg1-3ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-server2-2", ver:"2.6.1+dfsg1-3ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-client2-2", ver:"2.8.1+dfsg1-0ubuntu1.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreerdp-server2-2", ver:"2.8.1+dfsg1-0ubuntu1.1", rls:"UBUNTU22.10"))) {
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
