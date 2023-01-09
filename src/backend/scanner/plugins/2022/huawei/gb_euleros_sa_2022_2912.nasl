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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2912");
  script_cve_id("CVE-2022-24805", "CVE-2022-24806", "CVE-2022-24807", "CVE-2022-24808", "CVE-2022-24809", "CVE-2022-24810");
  script_tag(name:"creation_date", value:"2022-12-30 04:14:46 +0000 (Fri, 30 Dec 2022)");
  script_version("2022-12-30T10:12:19+0000");
  script_tag(name:"last_modification", value:"2022-12-30 10:12:19 +0000 (Fri, 30 Dec 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for net-snmp (EulerOS-SA-2022-2912)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2912");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2912");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'net-snmp' package(s) announced via the EulerOS-SA-2022-2912 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"SNMP (Simple Network Management Protocol) is a protocol used fornetwork management. The NET-SNMP project includes various SNMP toolsan extensible agent, an SNMP library, tools for requesting or settinginformation from SNMP agents, tools for generating and handling SNMPtraps, a version of the netstat(CVE-2022-24805)

SNMP (Simple Network Management Protocol) is a protocol used fornetwork management. The NET-SNMP project includes various SNMP toolsan extensible agent, an SNMP library, tools for requesting or settinginformation from SNMP agents, tools for generating and handling SNMPtraps, a version of the netstat(CVE-2022-24808)

SNMP (Simple Network Management Protocol) is a protocol used fornetwork management. The NET-SNMP project includes various SNMP toolsan extensible agent, an SNMP library, tools for requesting or settinginformation from SNMP agents, tools for generating and handling SNMPtraps, a version of the netstat(CVE-2022-24810)

SNMP (Simple Network Management Protocol) is a protocol used fornetwork management. The NET-SNMP project includes various SNMP toolsan extensible agent, an SNMP library, tools for requesting or settinginformation from SNMP agents, tools for generating and handling SNMPtraps, a version of the netstat(CVE-2022-24809)

SNMP (Simple Network Management Protocol) is a protocol used fornetwork management. The NET-SNMP project includes various SNMP toolsan extensible agent, an SNMP library, tools for requesting or settinginformation from SNMP agents, tools for generating and handling SNMPtraps, a version of the netstat(CVE-2022-24807)

SNMP (Simple Network Management Protocol) is a protocol used fornetwork management. The NET-SNMP project includes various SNMP toolsan extensible agent, an SNMP library, tools for requesting or settinginformation from SNMP agents, tools for generating and handling SNMPtraps, a version of the netstat(CVE-2022-24806)");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Huawei EulerOS Virtualization release 2.10.0.");

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

if(release == "EULEROSVIRT-2.10.0") {

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.9~3.h6.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.9~3.h6.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-net-snmp", rpm:"python3-net-snmp~5.9~3.h6.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
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
