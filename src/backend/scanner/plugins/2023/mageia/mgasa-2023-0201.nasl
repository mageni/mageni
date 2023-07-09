# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0201");
  script_cve_id("CVE-2022-48425", "CVE-2023-2124", "CVE-2023-2156", "CVE-2023-2269", "CVE-2023-31084", "CVE-2023-3141", "CVE-2023-3212", "CVE-2023-32233", "CVE-2023-3268", "CVE-2023-34256", "CVE-2023-35788", "CVE-2023-35823", "CVE-2023-35824", "CVE-2023-35828", "CVE-2023-35829");
  script_tag(name:"creation_date", value:"2023-06-20 04:12:32 +0000 (Tue, 20 Jun 2023)");
  script_version("2023-06-26T05:06:06+0000");
  script_tag(name:"last_modification", value:"2023-06-26 05:06:06 +0000 (Mon, 26 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-23 21:19:00 +0000 (Fri, 23 Jun 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0201)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0201");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0201.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32001");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.111");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.112");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.113");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.114");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.115");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.116");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.117");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) announced via the MGASA-2023-0201 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update is based on upstream 5.15.117 and fixes at least
the following security issues:

In the Linux kernel through 6.2.7, fs/ntfs3/inode.c has an invalid kfree
because it does not validate MFT flags before replaying logs
(CVE-2022-48425).

An out-of-bounds memory access flaw was found in the Linux kernel's XFS file
system in how a user restores an XFS image after failure (with a dirty log
journal). This flaw allows a local user to crash or potentially escalate
their privileges on the system (CVE-2023-2124).

A flaw was found in the networking subsystem of the Linux kernel within
the handling of the RPL protocol. This issue results from the lack of
proper handling of user-supplied data, which can lead to an assertion
failure. This may allow an unauthenticated remote attacker to create a
denial of service condition on the system (CVE-2023-2156).

A denial of service problem was found, due to a possible recursive locking
scenario, resulting in a deadlock in table_clear in drivers/md/dm-ioctl.c
in the Linux Kernel Device Mapper-Multipathing sub-component
(CVE-2023-2269).

A use-after-free flaw was found in r592_remove in drivers/memstick/host/r592.c
in media access in the Linux Kernel. This flaw allows a local attacker to
crash the system at device disconnect, possibly leading to a kernel
information leak (CVE-2023-3141).

A NULL pointer dereference issue was found in the gfs2 file system in the
Linux kernel. It occurs on corrupt gfs2 file systems when the evict code
tries to reference the journal descriptor structure after it has been freed
and set to NULL. A privileged local user could use this flaw to cause a
kernel panic (CVE-2023-3212).

An out of bounds (OOB) memory access flaw was found in the Linux kernel in
relay_file_read_start_pos in kernel/relay.c in the relayfs. This flaw could
allow a local attacker to crash the system or leak kernel internal
information (CVE-2023-3268).

An issue was discovered in drivers/media/dvb-core/dvb_frontend.c in the
Linux kernel 6.2. There is a blocking operation when a task is in
!TASK_RUNNING. In dvb_frontend_get_event, wait_event_interruptible is
called, the condition is dvb_frontend_test_event(fepriv,events).
In dvb_frontend_test_event, down(&fepriv->sem) is called. However,
wait_event_interruptible would put the process to sleep, and
down(&fepriv->sem) may block the process (CVE-2023-31084).

In the Linux kernel through 6.3.1, a use-after-free in Netfilter
nf_tables when processing batch requests can be abused to perform arbitrary
read and write operations on kernel memory. Unprivileged local users can
obtain root privileges. This occurs because anonymous sets are mishandled
(CVE-2023-32233).

An issue was discovered in the Linux kernel before 6.3.3. There is an
out-of-bounds read in crc16 in lib/crc16.c when called from fs/ext4/super.c
because ext4_group_desc_csum does not properly check an ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-5.15.117-2.mga8", rpm:"kernel-desktop-5.15.117-2.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-5.15.117-2.mga8", rpm:"kernel-desktop-devel-5.15.117-2.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-5.15.117-2.mga8", rpm:"kernel-desktop586-5.15.117-2.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-5.15.117-2.mga8", rpm:"kernel-desktop586-devel-5.15.117-2.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-5.15.117-2.mga8", rpm:"kernel-server-5.15.117-2.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-5.15.117-2.mga8", rpm:"kernel-server-devel-5.15.117-2.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-5.15.117-2.mga8", rpm:"kernel-source-5.15.117-2.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~7.0.8~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~3.23~1.18.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf-devel", rpm:"lib64bpf-devel~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf0", rpm:"lib64bpf0~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf-devel", rpm:"libbpf-devel~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf0", rpm:"libbpf0~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~5.15.117~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.15.117-desktop-2.mga8", rpm:"virtualbox-kernel-5.15.117-desktop-2.mga8~7.0.8~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.15.117-server-2.mga8", rpm:"virtualbox-kernel-5.15.117-server-2.mga8~7.0.8~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~7.0.8~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~7.0.8~1.8.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.117-desktop-2.mga8", rpm:"xtables-addons-kernel-5.15.117-desktop-2.mga8~3.23~1.18.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.117-desktop586-2.mga8", rpm:"xtables-addons-kernel-5.15.117-desktop586-2.mga8~3.23~1.18.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.117-server-2.mga8", rpm:"xtables-addons-kernel-5.15.117-server-2.mga8~3.23~1.18.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~3.23~1.18.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~3.23~1.18.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~3.23~1.18.mga8", rls:"MAGEIA8"))) {
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
