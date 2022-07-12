# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.844615");
  script_version("2020-09-28T10:54:24+0000");
  script_cve_id("CVE-2017-9122", "CVE-2017-9123", "CVE-2017-9124", "CVE-2017-9126", "CVE-2017-9127", "CVE-2017-9128", "CVE-2017-9125");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-09-29 10:01:49 +0000 (Tue, 29 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-26 03:00:34 +0000 (Sat, 26 Sep 2020)");
  script_name("Ubuntu: Security Advisory for libquicktime (USN-4545-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04 LTS");

  script_xref(name:"USN", value:"4545-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-September/005654.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libquicktime'
  package(s) announced via the USN-4545-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libquicktime incorrectly handled certain malformed
MP4 files. If a user were tricked into opening a specially crafted MP4
file, a remote attacker could use this issue to cause a denial of service
(resource exhaustion). (CVE-2017-9122)

It was discovered that libquicktime incorrectly handled certain malformed
MP4 files. If a user were tricked into opening a specially crafted MP4
file, a remote attacker could use this issue to cause libquicktime to
crash, resulting in a denial of service. (CVE-2017-9123, CVE-2017-9124,
CVE-2017-9126, CVE-2017-9127, CVE-2017-9128)

It was discovered that libquicktime incorrectly handled certain malformed
MP4 files. If a user were tricked into opening a specially crafted MP4
file, a remote attacker could use this issue to cause a denial of service.
(CVE-2017-9125)");

  script_tag(name:"affected", value:"'libquicktime' package(s) on Ubuntu 16.04 LTS.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libquicktime2", ver:"2:1.2.4-7+deb8u1ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quicktime-utils", ver:"2:1.2.4-7+deb8u1ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"quicktime-x11utils", ver:"2:1.2.4-7+deb8u1ubuntu0.1", rls:"UBUNTU16.04 LTS"))) {
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