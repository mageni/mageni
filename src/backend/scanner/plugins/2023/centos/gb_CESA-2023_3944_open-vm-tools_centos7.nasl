# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884290");
  script_version("2023-08-04T05:06:23+0000");
  script_cve_id("CVE-2023-20867");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-08-04 05:06:23 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-07-30 01:02:42 +0000 (Sun, 30 Jul 2023)");
  script_name("CentOS: Security Advisory for open-vm-tools (CESA-2023:3944)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2023:3944");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2023-July/086397.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'open-vm-tools'
  package(s) announced via the CESA-2023:3944 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Open Virtual Machine Tools are the open source implementation of the
VMware Tools. They are a set of guest operating system virtualization
components that enhance performance and user experience of virtual
machines.

Security Fix(es):

  * open-vm-tools: authentication bypass vulnerability in the vgauth module
(CVE-2023-20867)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * [ESXi] [RHEL7] vmtoolsd task is blocked in the uninterruptible state
while attempting to delete (unlink) the file 'quiesce_manifest.xml'
(BZ#1880404)

  * [ESXi][RHEL7.9][open-vm-tools] Snapshot of the RHEL7 guest on the VMWare
ESXi hypervisor failed vm hangs (BZ#1994590)");

  script_tag(name:"affected", value:"'open-vm-tools' package(s) on CentOS 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~11.0.5~3.el7_9.6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop", rpm:"open-vm-tools-desktop~11.0.5~3.el7_9.6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-devel", rpm:"open-vm-tools-devel~11.0.5~3.el7_9.6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-test", rpm:"open-vm-tools-test~11.0.5~3.el7_9.6", rls:"CentOS7"))) {
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