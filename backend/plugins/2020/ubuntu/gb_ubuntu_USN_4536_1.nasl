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
  script_oid("1.3.6.1.4.1.25623.1.0.844611");
  script_version("2020-09-28T10:54:24+0000");
  script_cve_id("CVE-2019-16392", "CVE-2019-16394", "CVE-2019-11071", "CVE-2019-16391", "CVE-2017-15736", "CVE-2019-19830", "CVE-2019-16393");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-09-29 10:01:49 +0000 (Tue, 29 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-25 03:00:25 +0000 (Fri, 25 Sep 2020)");
  script_name("Ubuntu: Security Advisory for spip (USN-4536-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04 LTS");

  script_xref(name:"USN", value:"4536-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-September/005648.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spip'
  package(s) announced via the USN-4536-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Youssouf Boulouiz discovered that SPIP incorrectly handled login error
messages. A remote attacker could potentially exploit this to conduct
cross-site scripting (XSS) attacks. (CVE-2019-16392)

Gilles Vincent discovered that SPIP incorrectly handled password reset
requests. A remote attacker could possibly use this issue to cause SPIP to
enumerate registered users. (CVE-2019-16394)

Guillaume Fahrner discovered that SPIP did not properly sanitize input. A
remote authenticated attacker could possibly use this issue to execute
arbitrary code on the host server. (CVE-2019-11071)

Sylvain Lefevre discovered that SPIP incorrectly handled user
authorization. A remote attacker could possibly use this issue to modify
and publish content and modify the database. (CVE-2019-16391)

It was discovered that SPIP did not properly sanitize input. A remote
attacker could, through cross-site scripting (XSS) and PHP injection,
exploit this to inject arbitrary web script or HTML. (CVE-2017-15736)

Alexis Zucca discovered that SPIP incorrectly handled the media plugin. A
remote authenticated attacker could possibly use this issue to write to
the database. (CVE-2019-19830)

Christophe Laffont discovered that SPIP incorrectly handled redirect URLs.
An attacker could use this issue to cause SPIP to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2019-16393)");

  script_tag(name:"affected", value:"'spip' package(s) on Ubuntu 18.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"spip", ver:"3.1.4-4~deb9u3build0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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