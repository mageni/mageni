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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5821.4");
  script_tag(name:"creation_date", value:"2023-03-03 04:37:35 +0000 (Fri, 03 Mar 2023)");
  script_version("2023-03-06T10:10:02+0000");
  script_tag(name:"last_modification", value:"2023-03-06 10:10:02 +0000 (Mon, 06 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5821-4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5821-4");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5821-4");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2009130");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pip' package(s) announced via the USN-5821-4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5821-3 fixed a vulnerability in pip. The update introduced
a minor regression in Ubuntu 14.04 ESM, Ubuntu 16.04 ESM and
Ubuntu 18.04 LTS. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Sebastian Chnelik discovered that wheel incorrectly handled
 certain file names when validated against a regex expression.
 An attacker could possibly use this issue to cause a
 denial of service.");

  script_tag(name:"affected", value:"'python-pip' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-pip-whl", ver:"1.5.4-1ubuntu4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-pip", ver:"1.5.4-1ubuntu4+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip", ver:"1.5.4-1ubuntu4+esm4", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-pip-whl", ver:"8.1.1-2ubuntu0.6+esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-pip", ver:"8.1.1-2ubuntu0.6+esm5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip", ver:"8.1.1-2ubuntu0.6+esm5", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-pip-whl", ver:"9.0.1-2.3~ubuntu1.18.04.8", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-pip", ver:"9.0.1-2.3~ubuntu1.18.04.8", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-pip", ver:"9.0.1-2.3~ubuntu1.18.04.8", rls:"UBUNTU18.04 LTS"))) {
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
