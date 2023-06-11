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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0188");
  script_cve_id("CVE-2023-27783", "CVE-2023-27784", "CVE-2023-27785", "CVE-2023-27786", "CVE-2023-27787", "CVE-2023-27788", "CVE-2023-27789");
  script_tag(name:"creation_date", value:"2023-06-01 04:13:29 +0000 (Thu, 01 Jun 2023)");
  script_version("2023-06-01T09:09:48+0000");
  script_tag(name:"last_modification", value:"2023-06-01 09:09:48 +0000 (Thu, 01 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-23 17:26:00 +0000 (Thu, 23 Mar 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0188)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0188");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0188.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31926");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/UE3J4LKYFNKPKNSLDQK4JG36THQMQH3V/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpreplay' package(s) announced via the MGASA-2023-0188 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue found in TCPreplay tcprewrite v.4.4.3 allows a remote attacker to
cause a denial of service via the tcpedit_dlt_cleanup function at
plugins/dlt_plugins.c. (CVE-2023-27783)

An issue found in TCPReplay v.4.4.3 allows a remote attacker to cause a
denial of service via the read_hexstring function at the utils.c:309
endpoint. (CVE-2023-27784)

An issue found in TCPreplay TCPprep v.4.4.3 allows a remote attacker to
cause a denial of service via the parse endpoints function.
(CVE-2023-27785)

An issue found in TCPprep v.4.4.3 allows a remote attacker to cause a
denial of service via the macinstring function. (CVE-2023-27786)

An issue found in TCPprep v.4.4.3 allows a remote attacker to cause a
denial of service via the parse_list function at the list.c:81 endpoint.
(CVE-2023-27787)

An issue found in TCPrewrite v.4.4.3 allows a remote attacker to cause a
denial of service via the ports2PORT function at the portmap.c:69
endpoint. (CVE-2023-27788)

An issue found in TCPprep v.4.4.3 allows a remote attacker to cause a
denial of service via the cidr2cidr function at the cidr.c:178 endpoint.
(CVE-2023-27789)");

  script_tag(name:"affected", value:"'tcpreplay' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"tcpreplay", rpm:"tcpreplay~4.4.2~1.1.mga8", rls:"MAGEIA8"))) {
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
