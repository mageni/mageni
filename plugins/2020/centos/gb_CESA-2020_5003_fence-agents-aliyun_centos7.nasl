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
  script_oid("1.3.6.1.4.1.25623.1.0.883291");
  script_version("2020-11-19T07:38:10+0000");
  script_cve_id("CVE-2020-11078");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-11-19 11:32:07 +0000 (Thu, 19 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-19 04:01:14 +0000 (Thu, 19 Nov 2020)");
  script_name("CentOS: Security Advisory for fence-agents-aliyun (CESA-2020:5003)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2020:5003");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2020-November/035863.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fence-agents-aliyun'
  package(s) announced via the CESA-2020:5003 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The fence-agents packages provide a collection of scripts for handling
remote power management for cluster devices. They allow failed or
unreachable nodes to be forcibly restarted and removed from the cluster.

Security Fix(es):

  * python-httplib2: CRLF injection via an attacker controlled unescaped part
of uri for httplib2.Http.request function (CVE-2020-11078)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * fence_lpar: Long username, HMC hostname, or managed system name causes
failures [RHEL 7] (BZ#1860545)

  * InstanceHA does not evacuate instances created with private flavor in
tenant project (RHEL7) (BZ#1862024)");

  script_tag(name:"affected", value:"'fence-agents-aliyun' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-aliyun", rpm:"fence-agents-aliyun~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-all", rpm:"fence-agents-all~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-amt-ws", rpm:"fence-agents-amt-ws~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-apc", rpm:"fence-agents-apc~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-apc-snmp", rpm:"fence-agents-apc-snmp~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-aws", rpm:"fence-agents-aws~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-azure-arm", rpm:"fence-agents-azure-arm~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-bladecenter", rpm:"fence-agents-bladecenter~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-brocade", rpm:"fence-agents-brocade~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-cisco-mds", rpm:"fence-agents-cisco-mds~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-cisco-ucs", rpm:"fence-agents-cisco-ucs~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-common", rpm:"fence-agents-common~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-compute", rpm:"fence-agents-compute~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-drac5", rpm:"fence-agents-drac5~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-eaton-snmp", rpm:"fence-agents-eaton-snmp~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-emerson", rpm:"fence-agents-emerson~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-eps", rpm:"fence-agents-eps~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-gce", rpm:"fence-agents-gce~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-heuristics-ping", rpm:"fence-agents-heuristics-ping~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-hpblade", rpm:"fence-agents-hpblade~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-ibmblade", rpm:"fence-agents-ibmblade~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-ifmib", rpm:"fence-agents-ifmib~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-ilo2", rpm:"fence-agents-ilo2~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-ilo-moonshot", rpm:"fence-agents-ilo-moonshot~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-ilo-mp", rpm:"fence-agents-ilo-mp~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-ilo-ssh", rpm:"fence-agents-ilo-ssh~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-intelmodular", rpm:"fence-agents-intelmodular~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-ipdu", rpm:"fence-agents-ipdu~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-ipmilan", rpm:"fence-agents-ipmilan~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-kdump", rpm:"fence-agents-kdump~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-lpar", rpm:"fence-agents-lpar~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-mpath", rpm:"fence-agents-mpath~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-redfish", rpm:"fence-agents-redfish~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-rhevm", rpm:"fence-agents-rhevm~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-rsa", rpm:"fence-agents-rsa~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-rsb", rpm:"fence-agents-rsb~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-sbd", rpm:"fence-agents-sbd~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-scsi", rpm:"fence-agents-scsi~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-virsh", rpm:"fence-agents-virsh~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-vmware-rest", rpm:"fence-agents-vmware-rest~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-vmware-soap", rpm:"fence-agents-vmware-soap~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents-wti", rpm:"fence-agents-wti~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fence-agents", rpm:"fence-agents~4.2.1~41.el7_9.2", rls:"CentOS7"))) {
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