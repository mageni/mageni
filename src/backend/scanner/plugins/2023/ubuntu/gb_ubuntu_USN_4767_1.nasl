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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.4767.1");
  script_cve_id("CVE-2014-3005", "CVE-2016-10134", "CVE-2016-10742", "CVE-2016-4338", "CVE-2017-2824", "CVE-2017-2825", "CVE-2019-15132", "CVE-2020-11800", "CVE-2020-15803");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-21 20:15:00 +0000 (Sat, 21 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-4767-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4767-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4767-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zabbix' package(s) announced via the USN-4767-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fu Chuang discovered that Zabbix did not properly parse IPs. A remote
attacker could possibly use this issue to execute arbitrary code. This
issue only affected Ubuntu 14.04 ESM, Ubuntu 16.04 ESM and Ubuntu 18.04 ESM.
(CVE-2020-11800)

It was discovered that Zabbix incorrectly handled certain requests. A
remote attacker could possibly use this issue to execute arbitrary code.
This issue only affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM.
(CVE-2017-2824, CVE-2017-2825)

It was discovered that Zabbix incorrectly handled certain XML files. A
remote attacker could possibly use this issue to read arbitrary files or
potentially execute arbitrary code. This issue only affected
Ubuntu 14.04 ESM. (CVE-2014-3005)

It was discovered that Zabbix incorrectly handled certain inputs. A remote
attacker could possibly use this issue to execute arbitrary SQL commands.
This issue only affected Ubuntu 14.04 ESM. (CVE-2016-10134, CVE-2016-4338)

It was discovered that Zabbix incorrectly handled the request parameter. A
remote attacker could possibly use this issue to redirect requests to
external links. This issue only affected Ubuntu 14.04 ESM and
Ubuntu 18.04 ESM. (CVE-2016-10742)

It was discovered that Zabbix incorrectly handled failed login attempts. A
remote attacker could possibly use this issue to enumerate users.
(CVE-2019-15132)

It was discovered that Zabbix did not properly validate input. A remote
attacker could exploit this to conduct cross-site scripting (XSS) attacks.
This issue only affected Ubuntu 16.04 ESM, Ubuntu 18.04 ESM and
Ubuntu 20.04 ESM. (CVE-2020-15803)");

  script_tag(name:"affected", value:"'zabbix' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-agent", ver:"1:2.2.2+dfsg-1ubuntu1+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-frontend-php", ver:"1:2.2.2+dfsg-1ubuntu1+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-java-gateway", ver:"1:2.2.2+dfsg-1ubuntu1+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-mysql", ver:"1:2.2.2+dfsg-1ubuntu1+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-pgsql", ver:"1:2.2.2+dfsg-1ubuntu1+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-sqlite3", ver:"1:2.2.2+dfsg-1ubuntu1+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-mysql", ver:"1:2.2.2+dfsg-1ubuntu1+esm4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-pgsql", ver:"1:2.2.2+dfsg-1ubuntu1+esm4", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-agent", ver:"1:2.4.7+dfsg-2ubuntu2.1+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-frontend-php", ver:"1:2.4.7+dfsg-2ubuntu2.1+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-java-gateway", ver:"1:2.4.7+dfsg-2ubuntu2.1+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-mysql", ver:"1:2.4.7+dfsg-2ubuntu2.1+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-pgsql", ver:"1:2.4.7+dfsg-2ubuntu2.1+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-sqlite3", ver:"1:2.4.7+dfsg-2ubuntu2.1+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-mysql", ver:"1:2.4.7+dfsg-2ubuntu2.1+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-pgsql", ver:"1:2.4.7+dfsg-2ubuntu2.1+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-agent", ver:"1:3.0.12+dfsg-1ubuntu0.1~esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-frontend-php", ver:"1:3.0.12+dfsg-1ubuntu0.1~esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-java-gateway", ver:"1:3.0.12+dfsg-1ubuntu0.1~esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-mysql", ver:"1:3.0.12+dfsg-1ubuntu0.1~esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-pgsql", ver:"1:3.0.12+dfsg-1ubuntu0.1~esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-sqlite3", ver:"1:3.0.12+dfsg-1ubuntu0.1~esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-mysql", ver:"1:3.0.12+dfsg-1ubuntu0.1~esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-pgsql", ver:"1:3.0.12+dfsg-1ubuntu0.1~esm3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-agent", ver:"1:4.0.17+dfsg-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-frontend-php", ver:"1:4.0.17+dfsg-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-java-gateway", ver:"1:4.0.17+dfsg-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-mysql", ver:"1:4.0.17+dfsg-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-pgsql", ver:"1:4.0.17+dfsg-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-sqlite3", ver:"1:4.0.17+dfsg-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-mysql", ver:"1:4.0.17+dfsg-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-pgsql", ver:"1:4.0.17+dfsg-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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
