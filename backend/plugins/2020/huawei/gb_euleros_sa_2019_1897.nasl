# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1897");
  script_version("2020-01-23T12:26:09+0000");
  script_cve_id("CVE-2019-10153");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 12:26:09 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:26:09 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for fence-agents (EulerOS-SA-2019-1897)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP5");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1897");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'fence-agents' package(s) announced via the EulerOS-SA-2019-1897 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in fence-agents, prior to version 4.3.4, where using non-ASCII characters in a guest VM's comment or other fields would cause fence_rhevm to exit with an exception. In cluster environments, this could lead to preventing automated recovery or otherwise denying service to clusters of which that VM is a member.(CVE-2019-10153)");

  script_tag(name:"affected", value:"'fence-agents' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-all", rpm:"fence-agents-all~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-amt-ws", rpm:"fence-agents-amt-ws~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-apc", rpm:"fence-agents-apc~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-apc-snmp", rpm:"fence-agents-apc-snmp~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-bladecenter", rpm:"fence-agents-bladecenter~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-brocade", rpm:"fence-agents-brocade~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-cisco-mds", rpm:"fence-agents-cisco-mds~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-cisco-ucs", rpm:"fence-agents-cisco-ucs~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-common", rpm:"fence-agents-common~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-compute", rpm:"fence-agents-compute~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-drac5", rpm:"fence-agents-drac5~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-eaton-snmp", rpm:"fence-agents-eaton-snmp~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-emerson", rpm:"fence-agents-emerson~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-eps", rpm:"fence-agents-eps~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-heuristics-ping", rpm:"fence-agents-heuristics-ping~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-hpblade", rpm:"fence-agents-hpblade~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-ibmblade", rpm:"fence-agents-ibmblade~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-ifmib", rpm:"fence-agents-ifmib~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-ilo-moonshot", rpm:"fence-agents-ilo-moonshot~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-ilo-mp", rpm:"fence-agents-ilo-mp~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-ilo-ssh", rpm:"fence-agents-ilo-ssh~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-ilo2", rpm:"fence-agents-ilo2~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-intelmodular", rpm:"fence-agents-intelmodular~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-ipdu", rpm:"fence-agents-ipdu~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-ipmilan", rpm:"fence-agents-ipmilan~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-kdump", rpm:"fence-agents-kdump~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-mpath", rpm:"fence-agents-mpath~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-rhevm", rpm:"fence-agents-rhevm~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-rsa", rpm:"fence-agents-rsa~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-rsb", rpm:"fence-agents-rsb~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-sbd", rpm:"fence-agents-sbd~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-scsi", rpm:"fence-agents-scsi~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-vmware-rest", rpm:"fence-agents-vmware-rest~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-vmware-soap", rpm:"fence-agents-vmware-soap~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-wti", rpm:"fence-agents-wti~4.0.11~86.3.h1.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);