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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5771.1");
  script_cve_id("CVE-2016-2569", "CVE-2016-2570", "CVE-2016-2571", "CVE-2016-3948", "CVE-2018-1000024", "CVE-2018-1000027");
  script_tag(name:"creation_date", value:"2022-12-12 06:09:18 +0000 (Mon, 12 Dec 2022)");
  script_version("2022-12-12T06:09:18+0000");
  script_tag(name:"last_modification", value:"2022-12-12 06:09:18 +0000 (Mon, 12 Dec 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-17 16:15:00 +0000 (Wed, 17 Jul 2019)");

  script_name("Ubuntu: Security Advisory (USN-5771-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5771-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5771-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1999346");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid3' package(s) announced via the USN-5771-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3557-1 fixed vulnerabilities in Squid. This update introduced a regression
which could cause the cache log to be filled with many Vary loop messages. This
update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

Mathias Fischer discovered that Squid incorrectly handled certain long
strings in headers. A malicious remote server could possibly cause Squid to
crash, resulting in a denial of service. This issue was only addressed in
Ubuntu 16.04 LTS. (CVE-2016-2569)

William Lima discovered that Squid incorrectly handled XML parsing when
processing Edge Side Includes (ESI). A malicious remote server could
possibly cause Squid to crash, resulting in a denial of service. This issue
was only addressed in Ubuntu 16.04 LTS. (CVE-2016-2570)

Alex Rousskov discovered that Squid incorrectly handled response-parsing
failures. A malicious remote server could possibly cause Squid to crash,
resulting in a denial of service. This issue only applied to Ubuntu 16.04
LTS. (CVE-2016-2571)

Santiago Ruano Rincon discovered that Squid incorrectly handled certain
Vary headers. A remote attacker could possibly use this issue to cause
Squid to crash, resulting in a denial of service. This issue was only
addressed in Ubuntu 16.04 LTS. (CVE-2016-3948)

Louis Dion-Marcil discovered that Squid incorrectly handled certain Edge
Side Includes (ESI) responses. A malicious remote server could possibly
cause Squid to crash, resulting in a denial of service. (CVE-2018-1000024)

Louis Dion-Marcil discovered that Squid incorrectly handled certain Edge
Side Includes (ESI) responses. A malicious remote server could possibly
cause Squid to crash, resulting in a denial of service. (CVE-2018-1000027)");

  script_tag(name:"affected", value:"'squid3' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"3.5.12-1ubuntu7.16+esm1", rls:"UBUNTU16.04 LTS"))) {
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
