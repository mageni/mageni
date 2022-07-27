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
  script_oid("1.3.6.1.4.1.25623.1.0.844555");
  script_version("2020-09-02T06:38:34+0000");
  script_cve_id("CVE-2019-12520", "CVE-2019-12523", "CVE-2019-12524", "CVE-2019-18676");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-09-02 10:05:23 +0000 (Wed, 02 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-02 11:51:42 +0530 (Wed, 02 Sep 2020)");
  script_name("Ubuntu: Security Advisory for squid3 (USN-4446-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU16\.04 LTS)");

  script_xref(name:"USN", value:"4446-2");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-August/005579.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid3'
  package(s) announced via the USN-4446-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4446-1 fixed vulnerabilities in Squid. The update introduced a
regression when using Squid with the icap or ecap protocols. This update
fixes the problem.

We apologize for the inconvenience.

Original advisory details:

Jeriko One discovered that Squid incorrectly handled caching certain
requests. A remote attacker could possibly use this issue to perform
cache-injection attacks or gain access to reverse proxy features such as
ESI. (CVE-2019-12520)
Jeriko One and Kristoffer Danielsson discovered that Squid incorrectly
handled certain URN requests. A remote attacker could possibly use this
issue to bypass access checks. (CVE-2019-12523)
Jeriko One discovered that Squid incorrectly handled URL decoding. A remote
attacker could possibly use this issue to bypass certain rule checks.
(CVE-2019-12524)
Jeriko One and Kristoffer Danielsson discovered that Squid incorrectly
handled input validation. A remote attacker could use this issue to cause
Squid to crash, resulting in a denial of service. (CVE-2019-18676)");

  script_tag(name:"affected", value:"'squid3' package(s) on Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"3.5.27-1ubuntu1.8", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"3.5.12-1ubuntu7.13", rls:"UBUNTU16.04 LTS"))) {
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