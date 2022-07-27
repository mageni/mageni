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
  script_oid("1.3.6.1.4.1.25623.1.0.844939");
  script_version("2021-05-25T12:16:58+0000");
  script_cve_id("CVE-2021-2146", "CVE-2021-2154", "CVE-2021-2162", "CVE-2021-2164", "CVE-2021-2166", "CVE-2021-2169", "CVE-2021-2170", "CVE-2021-2171", "CVE-2021-2172", "CVE-2021-2179", "CVE-2021-2180", "CVE-2021-2193", "CVE-2021-2194", "CVE-2021-2196", "CVE-2021-2201", "CVE-2021-2203", "CVE-2021-2208", "CVE-2021-2212", "CVE-2021-2215", "CVE-2021-2217", "CVE-2021-2226", "CVE-2021-2230", "CVE-2021-2232", "CVE-2021-2278", "CVE-2021-2293", "CVE-2021-2298", "CVE-2021-2299", "CVE-2021-2300", "CVE-2021-2301", "CVE-2021-2304", "CVE-2021-2305", "CVE-2021-2307", "CVE-2021-2308");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-05-26 10:26:09 +0000 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-13 03:00:34 +0000 (Thu, 13 May 2021)");
  script_name("Ubuntu: Security Advisory for mysql-8.0 (USN-4952-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU20\.04 LTS|UBUNTU18\.04 LTS|UBUNTU20\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4952-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-May/006020.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-8.0'
  package(s) announced via the USN-4952-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 8.0.25 in Ubuntu 20.04 LTS, Ubuntu 20.10, and
Ubuntu 21.04. Ubuntu 18.04 LTS has been updated to MySQL 5.7.34.

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes.");


  script_tag(name:"affected", value:"'mysql-8.0' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-8.0", ver:"8.0.25-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.7", ver:"5.7.34-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-8.0", ver:"8.0.25-0ubuntu0.20.10.1", rls:"UBUNTU20.10"))) {
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
