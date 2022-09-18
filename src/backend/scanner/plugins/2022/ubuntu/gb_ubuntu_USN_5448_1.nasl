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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5448.1");
  script_cve_id("CVE-2017-10684", "CVE-2017-10685", "CVE-2017-11112", "CVE-2017-11113", "CVE-2017-13728", "CVE-2017-13729", "CVE-2017-13730", "CVE-2017-13731", "CVE-2017-13732", "CVE-2017-13733", "CVE-2017-13734");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-5448-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5448-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5448-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ncurses' package(s) announced via the USN-5448-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ncurses was not properly checking array bounds
when executing the fmt_entry function, which could result in an
out-of-bounds write. An attacker could possibly use this issue to
execute arbitrary code. (CVE-2017-10684)

It was discovered that ncurses was not properly checking user input,
which could result in it being treated as a format argument. An
attacker could possibly use this issue to expose sensitive
information or to execute arbitrary code. (CVE-2017-10685)

It was discovered that ncurses was incorrectly performing memory
management operations and was not blocking access attempts to
illegal memory locations. An attacker could possibly use this issue
to cause a denial of service. (CVE-2017-11112, CVE-2017-13729,
CVE-2017-13730, CVE-2017-13731, CVE-2017-13732, CVE-2017-13733,
CVE-2017-13734)

It was discovered that ncurses was not properly performing checks
on pointer values before attempting to access the related memory
locations, which could lead to NULL pointer dereferencing. An
attacker could possibly use this issue to cause a denial of service.
(CVE-2017-11113)

It was discovered that ncurses was incorrectly handling loops in
libtic, which could lead to the execution of an infinite loop. An
attacker could possibly use this issue to cause a denial of service.
(CVE-2017-13728)");

  script_tag(name:"affected", value:"'ncurses' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"lib32ncurses5", ver:"5.9+20140118-1ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32ncursesw5", ver:"5.9+20140118-1ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32tinfo5", ver:"5.9+20140118-1ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64ncurses5", ver:"5.9+20140118-1ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64tinfo5", ver:"5.9+20140118-1ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libncurses5", ver:"5.9+20140118-1ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libncursesw5", ver:"5.9+20140118-1ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtinfo5", ver:"5.9+20140118-1ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32ncurses5", ver:"5.9+20140118-1ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32ncursesw5", ver:"5.9+20140118-1ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32tinfo5", ver:"5.9+20140118-1ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ncurses-base", ver:"5.9+20140118-1ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ncurses-bin", ver:"5.9+20140118-1ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ncurses-term", ver:"5.9+20140118-1ubuntu1+esm1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"lib32ncurses5", ver:"6.0+20160213-1ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32ncursesw5", ver:"6.0+20160213-1ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32tinfo5", ver:"6.0+20160213-1ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64ncurses5", ver:"6.0+20160213-1ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64tinfo5", ver:"6.0+20160213-1ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libncurses5", ver:"6.0+20160213-1ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libncursesw5", ver:"6.0+20160213-1ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtinfo5", ver:"6.0+20160213-1ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32ncurses5", ver:"6.0+20160213-1ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32ncursesw5", ver:"6.0+20160213-1ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32tinfo5", ver:"6.0+20160213-1ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ncurses-base", ver:"6.0+20160213-1ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ncurses-bin", ver:"6.0+20160213-1ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ncurses-term", ver:"6.0+20160213-1ubuntu1+esm1", rls:"UBUNTU16.04 LTS"))) {
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
