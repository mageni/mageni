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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6140.1");
  script_cve_id("CVE-2022-41724", "CVE-2022-41725", "CVE-2023-24534", "CVE-2023-24537", "CVE-2023-24538", "CVE-2023-24539", "CVE-2023-24540", "CVE-2023-29400");
  script_tag(name:"creation_date", value:"2023-06-07 04:09:34 +0000 (Wed, 07 Jun 2023)");
  script_version("2023-06-07T05:05:00+0000");
  script_tag(name:"last_modification", value:"2023-06-07 05:05:00 +0000 (Wed, 07 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-22 18:22:00 +0000 (Mon, 22 May 2023)");

  script_name("Ubuntu: Security Advisory (USN-6140-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.10|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6140-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6140-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-1.19, golang-1.20' package(s) announced via the USN-6140-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Go did not properly manage memory under certain
circumstances. An attacker could possibly use this issue to cause a panic
resulting in a denial of service. This issue only affected golang-1.19 on
Ubuntu 22.10. (CVE-2022-41724, CVE-2023-24534, CVE-2023-24537)

It was discovered that Go did not properly validate the amount of memory
and disk files ReadForm can consume. An attacker could possibly use this
issue to cause a panic resulting in a denial of service. This issue only
affected golang-1.19 on Ubuntu 22.10. (CVE-2022-41725)

It was discovered that Go did not properly validate backticks (`) as
Javascript string delimiters, and did not escape them as expected. An
attacker could possibly use this issue to inject arbitrary Javascript code
into the Go template. This issue only affected golang-1.19 on Ubuntu 22.10.
(CVE-2023-24538)

It was discovered that Go did not properly validate the angle brackets in
CSS values. An attacker could possibly use this issue to inject arbitrary
CSS code. (CVE-2023-24539)

It was discovered that Go did not properly validate whitespace characters
in Javascript, and did not escape them as expected. An attacker could
possibly use this issue to inject arbitrary Javascript code into the Go
template. (CVE-2023-24540)

It was discovered that Go did not properly validate HTML attributes with
empty input. An attacker could possibly use this issue to inject arbitrary
HTML tags into the Go template. (CVE-2023-29400)");

  script_tag(name:"affected", value:"'golang-1.19, golang-1.20' package(s) on Ubuntu 22.10, Ubuntu 23.04.");

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

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.19-go", ver:"1.19.2-1ubuntu1.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.19-src", ver:"1.19.2-1ubuntu1.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.19", ver:"1.19.2-1ubuntu1.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.19-go", ver:"1.19.8-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.19-src", ver:"1.19.8-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.19", ver:"1.19.8-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.20-go", ver:"1.20.3-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.20-src", ver:"1.20.3-1ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.20", ver:"1.20.3-1ubuntu0.1", rls:"UBUNTU23.04"))) {
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
