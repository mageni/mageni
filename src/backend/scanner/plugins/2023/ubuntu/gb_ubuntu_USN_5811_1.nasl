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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5811.1");
  script_cve_id("CVE-2022-33070", "CVE-2023-22809");
  script_tag(name:"creation_date", value:"2023-01-19 04:10:57 +0000 (Thu, 19 Jan 2023)");
  script_version("2023-01-30T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-01-30 10:09:19 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-26 18:26:00 +0000 (Thu, 26 Jan 2023)");

  script_name("Ubuntu: Security Advisory (USN-5811-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5811-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5811-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the USN-5811-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matthieu Barjole and Victor Cutillas discovered that Sudo incorrectly
handled user-specified editors when using the sudoedit command. A local
attacker that has permission to use the sudoedit command could possibly use
this issue to edit arbitrary files. (CVE-2023-22809)

It was discovered that the Protobuf-c library, used by Sudo, incorrectly
handled certain arithmetic shifts. An attacker could possibly use this
issue to cause Sudo to crash, resulting in a denial of service. This issue
only affected Ubuntu 22.04 LTS. (CVE-2022-33070)");

  script_tag(name:"affected", value:"'sudo' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 22.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.8.21p2-3ubuntu1.5", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sudo", ver:"1.8.21p2-3ubuntu1.5", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.8.31-1ubuntu1.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sudo", ver:"1.8.31-1ubuntu1.4", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.9.9-1ubuntu2.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sudo", ver:"1.9.9-1ubuntu2.2", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.9.11p3-1ubuntu1.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sudo", ver:"1.9.11p3-1ubuntu1.1", rls:"UBUNTU22.10"))) {
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
