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
  script_oid("1.3.6.1.4.1.25623.1.0.845112");
  script_version("2021-10-28T14:01:13+0000");
  script_cve_id("CVE-2021-2478", "CVE-2021-2479", "CVE-2021-2481", "CVE-2021-35546", "CVE-2021-35575", "CVE-2021-35577", "CVE-2021-35584", "CVE-2021-35591", "CVE-2021-35596", "CVE-2021-35597", "CVE-2021-35602", "CVE-2021-35604", "CVE-2021-35607", "CVE-2021-35608", "CVE-2021-35610", "CVE-2021-35612", "CVE-2021-35613", "CVE-2021-35622", "CVE-2021-35623", "CVE-2021-35624", "CVE-2021-35625", "CVE-2021-35626", "CVE-2021-35627", "CVE-2021-35628", "CVE-2021-35630", "CVE-2021-35631", "CVE-2021-35632", "CVE-2021-35633", "CVE-2021-35634", "CVE-2021-35635", "CVE-2021-35636", "CVE-2021-35637", "CVE-2021-35638", "CVE-2021-35639", "CVE-2021-35640", "CVE-2021-35641", "CVE-2021-35642", "CVE-2021-35643", "CVE-2021-35644", "CVE-2021-35645", "CVE-2021-35646", "CVE-2021-35647", "CVE-2021-35648");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-10-29 11:15:42 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-26 12:33:00 +0000 (Tue, 26 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-26 01:00:29 +0000 (Tue, 26 Oct 2021)");
  script_name("Ubuntu: Security Advisory for mysql-8.0 (USN-5123-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU20\.04 LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5123-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-October/006252.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-8.0'
  package(s) announced via the USN-5123-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in MySQL and this update includes
new upstream MySQL versions to fix these issues.

MySQL has been updated to 8.0.27 in Ubuntu 20.04 LTS, Ubuntu 21.04, and
Ubuntu 21.10. Ubuntu 18.04 LTS has been updated to MySQL 5.7.36.

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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.7", ver:"5.7.36-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-8.0", ver:"8.0.27-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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
