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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5795.2");
  script_cve_id("CVE-2022-24805", "CVE-2022-24806", "CVE-2022-24807", "CVE-2022-24808", "CVE-2022-24809", "CVE-2022-24810", "CVE-2022-44792", "CVE-2022-44793");
  script_tag(name:"creation_date", value:"2023-01-17 04:10:19 +0000 (Tue, 17 Jan 2023)");
  script_version("2023-01-17T10:10:58+0000");
  script_tag(name:"last_modification", value:"2023-01-17 10:10:58 +0000 (Tue, 17 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-08 04:23:00 +0000 (Tue, 08 Nov 2022)");

  script_name("Ubuntu: Security Advisory (USN-5795-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5795-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5795-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp' package(s) announced via the USN-5795-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5795-1 and 5543-1 fixed several vulnerabilities in Net-SNMP. This update provides
the corresponding update for Ubuntu 14.04 ESM and Ubuntu 16.04 ESM.

Original advisory details:

 It was discovered that Net-SNMP incorrectly handled certain requests. A
 remote attacker could possibly use these issues to cause Net-SNMP to crash,
 resulting in a denial of service.

 Yu Zhang and Nanyu Zhong discovered that Net-SNMP incorrectly handled
 memory operations when processing certain requests. A remote attacker could
 use this issue to cause Net-SNMP to crash, resulting in a denial of
 service, or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsnmp30", ver:"5.7.2~dfsg-8.1ubuntu3.3+esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"snmp", ver:"5.7.2~dfsg-8.1ubuntu3.3+esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"snmpd", ver:"5.7.2~dfsg-8.1ubuntu3.3+esm3", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsnmp30", ver:"5.7.3+dfsg-1ubuntu4.6+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"snmp", ver:"5.7.3+dfsg-1ubuntu4.6+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"snmpd", ver:"5.7.3+dfsg-1ubuntu4.6+esm1", rls:"UBUNTU16.04 LTS"))) {
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
