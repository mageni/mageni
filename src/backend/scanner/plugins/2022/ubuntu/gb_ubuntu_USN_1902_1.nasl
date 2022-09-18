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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2013.1902.1");
  script_cve_id("CVE-2013-4073");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1902-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|12\.10|13\.04)");

  script_xref(name:"Advisory-ID", value:"USN-1902-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1902-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby1.8, ruby1.9.1' package(s) announced via the USN-1902-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"William (B.J.) Snow Orvis discovered that Ruby incorrectly verified the
hostname in SSL certificates. An attacker could trick Ruby into trusting a
rogue server certificate, which was signed by a trusted certificate
authority, to perform a machine-in-the-middle attack.");

  script_tag(name:"affected", value:"'ruby1.8, ruby1.9.1' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.7.352-2ubuntu1.3", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.9.1", ver:"1.9.3.0-1ubuntu2.7", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.7.352-2ubuntu1.3", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1", ver:"1.9.3.0-1ubuntu2.7", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.7.358-4ubuntu0.3", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.9.1", ver:"1.9.3.194-1ubuntu1.5", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.7.358-4ubuntu0.3", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1", ver:"1.9.3.194-1ubuntu1.5", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.7.358-7ubuntu1.1", rls:"UBUNTU13.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libruby1.9.1", ver:"1.9.3.194-8.1ubuntu1.1", rls:"UBUNTU13.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.7.358-7ubuntu1.1", rls:"UBUNTU13.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby1.9.1", ver:"1.9.3.194-8.1ubuntu1.1", rls:"UBUNTU13.04"))) {
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
