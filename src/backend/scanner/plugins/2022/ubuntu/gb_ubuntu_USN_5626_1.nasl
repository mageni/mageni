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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5626.1");
  script_cve_id("CVE-2022-2795", "CVE-2022-2881", "CVE-2022-2906", "CVE-2022-3080", "CVE-2022-38177", "CVE-2022-38178");
  script_tag(name:"creation_date", value:"2022-09-22 04:39:28 +0000 (Thu, 22 Sep 2022)");
  script_version("2022-09-22T10:44:54+0000");
  script_tag(name:"last_modification", value:"2022-09-22 10:44:54 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5626-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5626-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5626-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9' package(s) announced via the USN-5626-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yehuda Afek, Anat Bremler-Barr, and Shani Stajnrod discovered that Bind
incorrectly handled large delegations. A remote attacker could possibly use
this issue to reduce performance, leading to a denial of service.
(CVE-2022-2795)

It was discovered that Bind incorrectly handled statistics requests. A
remote attacker could possibly use this issue to obtain sensitive memory
contents, or cause a denial of service. This issue only affected Ubuntu
22.04 LTS. (CVE-2022-2881)

It was discovered that Bind incorrectly handled memory when processing
certain Diffie-Hellman key exchanges. A remote attacker could use this
issue to consume resources, leading to a denial of service. This issue only
affected Ubuntu 22.04 LTS. (CVE-2022-2906)

Maksym Odinintsev discovered that Bind incorrectly handled answers from
cache when configured with a zero stale-answer-timeout. A remote attacker
could possibly use this issue to cause Bind to crash, resulting in a denial
of service. This issue only affected Ubuntu 22.04 LTS. (CVE-2022-3080)

It was discovered that Bind incorrectly handled memory when processing
ECDSA DNSSEC verification. A remote attacker could use this issue to
consume resources, leading to a denial of service. This issue only affected
Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2022-38177)

It was discovered that Bind incorrectly handled memory when processing
EDDSA DNSSEC verification. A remote attacker could use this issue to
consume resources, leading to a denial of service. (CVE-2022-38178)");

  script_tag(name:"affected", value:"'bind9' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.11.3+dfsg-1ubuntu1.18", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.16.1-0ubuntu2.11", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"bind9", ver:"1:9.18.1-1ubuntu1.2", rls:"UBUNTU22.04 LTS"))) {
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
