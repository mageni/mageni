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
  script_oid("1.3.6.1.4.1.25623.1.0.844508");
  script_version("2020-07-24T07:28:01+0000");
  script_cve_id("CVE-2019-20839", "CVE-2019-20840", "CVE-2020-14396", "CVE-2020-14397", "CVE-2020-14398", "CVE-2020-14399", "CVE-2020-14400", "CVE-2020-14401", "CVE-2020-14402", "CVE-2020-14403", "CVE-2020-14404", "CVE-2020-14405");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-07-24 10:05:16 +0000 (Fri, 24 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-24 03:00:30 +0000 (Fri, 24 Jul 2020)");
  script_name("Ubuntu: Security Advisory for libvncserver (USN-4434-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU16\.04 LTS|UBUNTU20\.04 LTS)");

  script_xref(name:"USN", value:"4434-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-July/005526.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvncserver'
  package(s) announced via the USN-4434-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ramin Farajpour Cami discovered that LibVNCServer incorrectly handled
certain malformed unix socket names. A remote attacker could exploit this
with a crafted socket name, leading to a denial of service, or possibly
execute arbitrary code. (CVE-2019-20839)

It was discovered that LibVNCServer did not properly access byte-aligned
data. A remote attacker could possibly use this issue to cause
LibVNCServer to crash, resulting in a denial of service. This issue only
affected Ubuntu 18.04 LTS and Ubuntu 16.04 LTS. (CVE-2019-20840)

Christian Beier discovered that LibVNCServer incorrectly handled anonymous
TLS connections. A remote attacker could possibly use this issue to cause
LibVNCServer to crash, resulting in a denial of service. This issue only
affected Ubuntu 20.04 LTS. (CVE-2020-14396)

It was discovered that LibVNCServer incorrectly handled region clipping. A
remote attacker could possibly use this issue to cause LibVNCServer to
crash, resulting in a denial of service. (CVE-2020-14397)

It was discovered that LibVNCServer did not properly reset incorrectly
terminated TCP connections. A remote attacker could possibly use this
issue to cause an infinite loop, resulting in a denial of service.
(CVE-2020-14398)

It was discovered that LibVNCServer did not properly access byte-aligned
data. A remote attacker could possibly use this issue to cause
LibVNCServer to crash, resulting in a denial of service. (CVE-2020-14399,
CVE-2020-14400)

It was discovered that LibVNCServer incorrectly handled screen scaling on
the server side. A remote attacker could use this issue to cause
LibVNCServer to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2020-14401)

It was discovered that LibVNCServer incorrectly handled encodings. A
remote attacker could use this issue to cause LibVNCServer to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2020-14402, CVE-2020-14403, CVE-2020-14404)

It was discovered that LibVNCServer incorrectly handled TextChat messages.
A remote attacker could possibly use this issue to cause LibVNCServer to
crash, resulting in a denial of service. (CVE-2020-14405)");

  script_tag(name:"affected", value:"'libvncserver' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libvncclient1", ver:"0.9.11+dfsg-1ubuntu1.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncserver1", ver:"0.9.11+dfsg-1ubuntu1.3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libvncclient1", ver:"0.9.10+dfsg-3ubuntu0.16.04.5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncserver1", ver:"0.9.10+dfsg-3ubuntu0.16.04.5", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libvncclient1", ver:"0.9.12+dfsg-9ubuntu0.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libvncserver1", ver:"0.9.12+dfsg-9ubuntu0.2", rls:"UBUNTU20.04 LTS"))) {
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