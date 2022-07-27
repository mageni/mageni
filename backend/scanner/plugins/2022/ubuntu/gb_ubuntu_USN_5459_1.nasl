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
  script_oid("1.3.6.1.4.1.25623.1.0.845396");
  script_version("2022-06-15T04:37:18+0000");
  script_cve_id("CVE-2020-14342", "CVE-2021-20208", "CVE-2022-27239", "CVE-2022-29869");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-06-15 10:13:29 +0000 (Wed, 15 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-03 01:00:31 +0000 (Fri, 03 Jun 2022)");
  script_name("Ubuntu: Security Advisory for cifs-utils (USN-5459-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU21\.10|UBUNTU18\.04 LTS|UBUNTU22\.04 LTS|UBUNTU20\.04 LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5459-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2022-June/006605.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cifs-utils'
  package(s) announced via the USN-5459-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aurélien Aptel discovered that cifs-utils invoked a shell when requesting a
password. In certain environments, a local attacker could possibly use this
issue to escalate privileges. This issue only affected Ubuntu 18.04 LTS and
Ubuntu 20.04 LTS. (CVE-2020-14342)

It was discovered that cifs-utils incorrectly used host credentials when
mounting a krb5 CIFS file system from within a container. An attacker
inside a container could possibly use this issue to obtain access to
sensitive information. This issue only affected Ubuntu 18.04 LTS and Ubuntu
20.04 LTS. (CVE-2021-20208)

It was discovered that cifs-utils incorrectly handled certain command-line
arguments. A local attacker could possibly use this issue to obtain root
privileges. (CVE-2022-27239)

It was discovered that cifs-utils incorrectly handled verbose logging. A
local attacker could possibly use this issue to obtain sensitive
information. (CVE-2022-29869)");

  script_tag(name:"affected", value:"'cifs-utils' package(s) on Ubuntu 22.04 LTS, Ubuntu 21.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS.");

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

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"cifs-utils", ver:"2:6.11-3.1ubuntu0.1", rls:"UBUNTU21.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cifs-utils", ver:"2:6.8-1ubuntu1.2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cifs-utils", ver:"2:6.14-1ubuntu0.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cifs-utils", ver:"2:6.9-1ubuntu0.2", rls:"UBUNTU20.04 LTS"))) {
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