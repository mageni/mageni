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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.4780.1");
  script_cve_id("CVE-2015-9099", "CVE-2015-9100", "CVE-2015-9101", "CVE-2017-11720", "CVE-2017-13712", "CVE-2017-15018", "CVE-2017-15019", "CVE-2017-15045", "CVE-2017-8419", "CVE-2017-9410", "CVE-2017-9411", "CVE-2017-9412");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-31 01:29:00 +0000 (Thu, 31 Aug 2017)");

  script_name("Ubuntu: Security Advisory (USN-4780-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4780-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4780-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lame' package(s) announced via the USN-4780-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that LAME incorrectly handled certain audio files. A
remote attacker could possibly use this issue to cause a denial of service. Eight
vulnerabilities (CVE-2015-9099, CVE-2015-9100, CVE-2015-9101, CVE-2017-15018,
CVE-2017-11720, CVE-2017-8419, CVE-2017-9412, CVE-2017-15045) only affected Ubuntu 14.04
ESM, two vulnerabilities (CVE-2017-9410 and CVE-2017-9411) only affected Ubuntu
16.04 ESM, and one vulnerability (CVE-2017-15019) affected both Ubuntu 14.04
ESM and Ubuntu 16.04.");

  script_tag(name:"affected", value:"'lame' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"lame", ver:"3.99.5+repack1-3ubuntu1+esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmp3lame0", ver:"3.99.5+repack1-3ubuntu1+esm3", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"lame", ver:"3.99.5+repack1-9ubuntu0.1~esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmp3lame0", ver:"3.99.5+repack1-9ubuntu0.1~esm2", rls:"UBUNTU16.04 LTS"))) {
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
