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
  script_oid("1.3.6.1.4.1.25623.1.0.844622");
  script_version("2020-10-01T09:58:23+0000");
  script_cve_id("CVE-2020-15049", "CVE-2020-15810", "CVE-2020-15811", "CVE-2020-24606");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-10-02 10:00:49 +0000 (Fri, 02 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-09-29 03:01:32 +0000 (Tue, 29 Sep 2020)");
  script_name("Ubuntu: Security Advisory for squid3 (USN-4551-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU16\.04 LTS)");

  script_xref(name:"USN", value:"4551-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-September/005661.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid3'
  package(s) announced via the USN-4551-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alex Rousskov and Amit Klein discovered that Squid incorrectly handled
certain Content-Length headers. A remote attacker could possibly use this
issue to perform an HTTP request smuggling attack, resulting in cache
poisoning. (CVE-2020-15049)

Amit Klein discovered that Squid incorrectly validated certain data. A
remote attacker could possibly use this issue to perform an HTTP request
smuggling attack, resulting in cache poisoning. (CVE-2020-15810)

Régis Leroy discovered that Squid incorrectly validated certain data. A
remote attacker could possibly use this issue to perform an HTTP request
splitting attack, resulting in cache poisoning. (CVE-2020-15811)

Lubos Uhliarik discovered that Squid incorrectly handled certain Cache
Digest response messages sent by trusted peers. A remote attacker could
possibly use this issue to cause Squid to consume resources, resulting in a
denial of service. (CVE-2020-24606)");

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

  if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"3.5.27-1ubuntu1.9", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"3.5.12-1ubuntu7.15", rls:"UBUNTU16.04 LTS"))) {
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