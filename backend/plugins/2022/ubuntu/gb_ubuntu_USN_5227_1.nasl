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
  script_oid("1.3.6.1.4.1.25623.1.0.845196");
  script_version("2022-01-14T07:06:50+0000");
  script_cve_id("CVE-2021-23437", "CVE-2021-34552", "CVE-2022-22815", "CVE-2022-22816", "CVE-2022-22817");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-01-14 11:23:55 +0000 (Fri, 14 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-14 02:00:55 +0000 (Fri, 14 Jan 2022)");
  script_name("Ubuntu: Security Advisory for pillow (USN-5227-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU20\.04 LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5227-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2022-January/006350.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pillow'
  package(s) announced via the USN-5227-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Pillow incorrectly handled certain image files. If a
user or automated system were tricked into opening a specially-crafted
file, a remote attacker could cause Pillow to hang, resulting in a denial
of service. (CVE-2021-23437)

It was discovered that Pillow incorrectly handled certain image files. If a
user or automated system were tricked into opening a specially-crafted
file, a remote attacker could cause Pillow to crash, resulting in a denial
of service. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and
Ubuntu 21.04. (CVE-2021-34552)

It was discovered that Pillow incorrectly handled certain image files. If a
user or automated system were tricked into opening a specially-crafted
file, a remote attacker could cause Pillow to crash, resulting in a denial
of service, or possibly execute arbitrary code. (CVE-2022-22815)

It was discovered that Pillow incorrectly handled certain image files. If a
user or automated system were tricked into opening a specially-crafted
file, a remote attacker could cause Pillow to crash, resulting in a denial
of service. (CVE-2022-22816)

It was discovered that Pillow incorrectly handled certain image files. If a
user or automated system were tricked into opening a specially-crafted
file, a remote attacker could cause Pillow to crash, resulting in a denial
of service, or possibly execute arbitrary code. (CVE-2022-22817)");

  script_tag(name:"affected", value:"'pillow' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-pil", ver:"5.1.0-1ubuntu0.7", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pil", ver:"5.1.0-1ubuntu0.7", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-pil", ver:"7.0.0-4ubuntu0.5", rls:"UBUNTU20.04 LTS"))) {
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
