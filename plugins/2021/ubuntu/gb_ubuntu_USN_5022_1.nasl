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
  script_oid("1.3.6.1.4.1.25623.1.0.845011");
  script_version("2021-08-03T06:52:21+0000");
  script_cve_id("CVE-2021-2339", "CVE-2021-2340", "CVE-2021-2342", "CVE-2021-2352", "CVE-2021-2354", "CVE-2021-2356", "CVE-2021-2357", "CVE-2021-2367", "CVE-2021-2370", "CVE-2021-2372", "CVE-2021-2374", "CVE-2021-2383", "CVE-2021-2384", "CVE-2021-2385", "CVE-2021-2387", "CVE-2021-2389", "CVE-2021-2390", "CVE-2021-2399", "CVE-2021-2402", "CVE-2021-2410", "CVE-2021-2417", "CVE-2021-2418", "CVE-2021-2422", "CVE-2021-2424", "CVE-2021-2425", "CVE-2021-2426", "CVE-2021-2427", "CVE-2021-2429", "CVE-2021-2437", "CVE-2021-2440", "CVE-2021-2441");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"2021-08-03 10:35:54 +0000 (Tue, 03 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-07-27 03:00:36 +0000 (Tue, 27 Jul 2021)");
  script_name("Ubuntu: Security Advisory for mysql-8.0 (USN-5022-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU20\.04 LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5022-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-July/006119.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-8.0'
  package(s) announced via the USN-5022-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 8.0.26 in Ubuntu 20.04 LTS and Ubuntu 21.04.
Ubuntu 18.04 LTS has been updated to MySQL 5.7.35.

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes.");

  script_tag(name:"affected", value:"'mysql-8.0' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.7", ver:"5.7.35-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-8.0", ver:"8.0.26-0ubuntu0.20.04.2", rls:"UBUNTU20.04 LTS"))) {
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
