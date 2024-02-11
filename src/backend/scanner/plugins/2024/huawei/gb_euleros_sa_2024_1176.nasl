# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1176");
  script_cve_id("CVE-2023-1829", "CVE-2023-31085", "CVE-2023-39198", "CVE-2023-6546", "CVE-2023-6606", "CVE-2023-6931", "CVE-2023-6932");
  script_tag(name:"creation_date", value:"2024-02-09 04:23:45 +0000 (Fri, 09 Feb 2024)");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-19 19:16:35 +0000 (Wed, 19 Apr 2023)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-1176)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1176");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1176");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-1176 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A race condition was found in the GSM 0710 tty multiplexor in the Linux kernel. This issue occurs when two threads execute the GSMIOC_SETCONF ioctl on the same tty file descriptor with the gsm line discipline enabled, and can lead to a use-after-free problem on a struct gsm_dlci while restarting the gsm mux. This could allow a local unprivileged user to escalate their privileges on the system.(CVE-2023-6546)

A heap out-of-bounds write vulnerability in the Linux kernel's Performance Events system component can be exploited to achieve local privilege escalation.A perf_event's read_size can overflow, leading to an heap out-of-bounds increment or write in perf_read_group().We recommend upgrading past commit 382c27f4ed28f803b1f1473ac2d8db0afc795a1b.(CVE-2023-6931)

A use-after-free vulnerability in the Linux kernel's ipv4: igmp component can be exploited to achieve local privilege escalation.A race condition can be exploited to cause a timer be mistakenly registered on a RCU read locked object which is freed by another thread.We recommend upgrading past commit e2b706c691905fe78468c361aaabc719d0a496f1.(CVE-2023-6932)

An out-of-bounds read vulnerability was found in smbCalcSize in fs/smb/client/netmisc.c in the Linux Kernel. This issue could allow a local attacker to crash the system or leak internal kernel information.(CVE-2023-6606)

A race condition was found in the QXL driver in the Linux kernel. The qxl_mode_dumb_create() function dereferences the qobj returned by the qxl_gem_object_create_with_handle(), but the handle is the only one holding a reference to it. This flaw allows an attacker to guess the returned handle value and trigger a use-after-free issue, potentially leading to a denial of service or privilege escalation.(CVE-2023-39198)

An issue was discovered in drivers/mtd/ubi/cdev.c in the Linux kernel 6.2. There is a divide-by-zero error in do_div(sz,mtd->erasesize), used indirectly by ctrl_cdev_ioctl, when mtd->erasesize is 0.(CVE-2023-31085)

A use-after-free vulnerability in the Linux Kernel traffic control index filter (tcindex) can be exploited to achieve local privilege escalation. The tcindex_delete function which does not properly deactivate filters in case of a perfect hashes while deleting the underlying structure which can later lead to double freeing the structure. A local attacker user can use this vulnerability to elevate its privileges to root.We recommend upgrading past commit 8c710f75256bb3cf05ac7b1672c82b92c43f3d28.(CVE-2023-1829)");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP9.");

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

if(release == "EULEROS-2.0SP9") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2103.1.0.h1144.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2103.1.0.h1144.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2103.1.0.h1144.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2103.1.0.h1144.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
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
