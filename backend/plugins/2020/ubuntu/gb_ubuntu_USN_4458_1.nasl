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
  script_oid("1.3.6.1.4.1.25623.1.0.844536");
  script_version("2020-08-14T06:59:33+0000");
  script_cve_id("CVE-2020-1927", "CVE-2020-1934", "CVE-2020-9490", "CVE-2020-11984", "CVE-2020-11993");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-14 09:58:14 +0000 (Fri, 14 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-14 03:00:16 +0000 (Fri, 14 Aug 2020)");
  script_name("Ubuntu: Security Advisory for apache2 (USN-4458-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU16\.04 LTS|UBUNTU20\.04 LTS)");

  script_xref(name:"USN", value:"4458-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-August/005558.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2'
  package(s) announced via the USN-4458-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fabrice Perez discovered that the Apache mod_rewrite module incorrectly
handled certain redirects. A remote attacker could possibly use this issue
to perform redirects to an unexpected URL. (CVE-2020-1927)

Chamal De Silva discovered that the Apache mod_proxy_ftp module incorrectly
handled memory when proxying to a malicious FTP server. A remote attacker
could possibly use this issue to obtain sensitive information.
(CVE-2020-1934)

Felix Wilhelm discovered that the HTTP/2 implementation in Apache did not
properly handle certain Cache-Digest headers. A remote attacker could
possibly use this issue to cause Apache to crash, resulting in a denial of
service. This issue only affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS.
(CVE-2020-9490)

Felix Wilhelm discovered that the Apache mod_proxy_uwsgi module incorrectly
handled large headers. A remote attacker could use this issue to obtain
sensitive information or possibly execute arbitrary code. This issue only
affected Ubuntu 20.04 LTS. (CVE-2020-11984)

Felix Wilhelm discovered that the HTTP/2 implementation in Apache did not
properly handle certain logging statements. A remote attacker could
possibly use this issue to cause Apache to crash, resulting in a denial of
service. This issue only affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS.
(CVE-2020-11993)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.29-1ubuntu4.14", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.29-1ubuntu4.14", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.18-2ubuntu3.17", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.18-2ubuntu3.17", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.41-4ubuntu3.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.41-4ubuntu3.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-proxy-uwsgi", ver:"2.4.41-4ubuntu3.1", rls:"UBUNTU20.04 LTS"))) {
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