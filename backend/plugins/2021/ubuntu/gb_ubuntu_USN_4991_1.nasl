# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.844978");
  script_version("2021-07-06T12:11:22+0000");
  script_cve_id("CVE-2017-8872", "CVE-2019-20388", "CVE-2020-24977", "CVE-2021-3517", "CVE-2021-3516", "CVE-2021-3518", "CVE-2021-3537", "CVE-2021-3541");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-06 12:11:22 +0000 (Tue, 06 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-06-18 03:00:27 +0000 (Fri, 18 Jun 2021)");
  script_name("Ubuntu: Security Advisory for libxml2 (USN-4991-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU20\.04 LTS|UBUNTU18\.04 LTS|UBUNTU20\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4991-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-June/006076.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2'
  package(s) announced via the USN-4991-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yunho Kim discovered that libxml2 incorrectly handled certain error
conditions. A remote attacker could exploit this with a crafted XML file to
cause a denial of service, or possibly cause libxml2 to expose sensitive
information. This issue only affected Ubuntu 14.04 ESM, and Ubuntu 16.04
ESM. (CVE-2017-8872)

Zhipeng Xie discovered that libxml2 incorrectly handled certain XML
schemas. A remote attacker could possibly use this issue to cause a denial
of service. This issue only affected Ubuntu 14.04 ESM, Ubuntu 16.04 ESM,
and Ubuntu 18.04 LTS. (CVE-2019-20388)

It was discovered that libxml2 incorrectly handled invalid UTF-8 input. A
remote attacker could possibly exploit this with a crafted XML file to
cause libxml2 to crash, resulting in a denial of service. This issue only
affected Ubuntu 14.04 ESM, Ubuntu 16.04 ESM, Ubuntu 18.04 LTS, Ubuntu 20.04
LTS and Ubuntu 20.10. (CVE-2020-24977)

It was discovered that libxml2 incorrectly handled invalid UTF-8 input. A
remote attacker could possibly exploit this with a crafted XML file to
cause libxml2 to crash, resulting in a denial of service. (CVE-2021-3517)

It was discovered that libxml2 did not properly handle certain crafted XML
files. A local attacker could exploit this with a crafted input to cause
libxml2 to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2021-3516, CVE-2021-3518)

It was discovered that libxml2 incorrectly handled error states. A remote
attacker could exploit this with a crafted XML file to cause libxml2 to
crash, resulting in a denial of service. (CVE-2021-3537)

Sebastian Pipping discovered that libxml2 did not properly handle certain
crafted XML files. A remote attacker could exploit this with a crafted XML
file to cause libxml2 to crash, resulting in a denial of service. This
issue only affected Ubuntu 20.04 LTS, Ubuntu 20.10, and Ubuntu 21.04.
(CVE-2021-3541)");

  script_tag(name:"affected", value:"'libxml2' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libxml2", ver:"2.9.10+dfsg-5ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-utils", ver:"2.9.10+dfsg-5ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxml2", ver:"2.9.4+dfsg1-6.1ubuntu1.4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-utils", ver:"2.9.4+dfsg1-6.1ubuntu1.4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libxml2", ver:"2.9.10+dfsg-5ubuntu0.20.10.2", rls:"UBUNTU20.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-utils", ver:"2.9.10+dfsg-5ubuntu0.20.10.2", rls:"UBUNTU20.10"))) {
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