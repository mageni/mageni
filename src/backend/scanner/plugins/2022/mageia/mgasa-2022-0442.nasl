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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0442");
  script_cve_id("CVE-2022-2602", "CVE-2022-3524", "CVE-2022-3535", "CVE-2022-3542", "CVE-2022-3543", "CVE-2022-3564", "CVE-2022-3565", "CVE-2022-3594", "CVE-2022-3619", "CVE-2022-3623", "CVE-2022-3628", "CVE-2022-41849", "CVE-2022-41850", "CVE-2022-42895", "CVE-2022-42896", "CVE-2022-43945");
  script_tag(name:"creation_date", value:"2022-11-28 04:13:48 +0000 (Mon, 28 Nov 2022)");
  script_version("2022-11-28T04:13:48+0000");
  script_tag(name:"last_modification", value:"2022-11-28 04:13:48 +0000 (Mon, 28 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-20 12:49:00 +0000 (Thu, 20 Oct 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0442)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0442");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0442.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31148");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.75");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.76");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.77");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.78");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.79");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) announced via the MGASA-2022-0442 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update is based on upstream 5.15.79 and fixes at least the
following security issues:

A flaw was found in the Linux kernel. A race issue occurs between an
io_uring request and the Unix socket garbage collector, allowing an attacker
local privilege escalation (CVE-2022-2602).

A vulnerability was found in Linux Kernel. It has been declared as
problematic. Affected by this vulnerability is the function
ipv6_renew_options of the component IPv6 Handler. The manipulation leads
to memory leak. The attack can be launched remotely (CVE-2022-3524).

A vulnerability classified as problematic was found in Linux Kernel.
Affected by this vulnerability is the function mvpp2_dbgfs_port_init of
the file drivers/net/ethernet/marvell/mvpp2/mvpp2_debugfs.c of the
component mvpp2. The manipulation leads to memory leak (CVE-2022-3535).

A vulnerability classified as problematic was found in Linux Kernel. This
vulnerability affects the function bnx2x_tpa_stop of the file drivers/net/
ethernet/broadcom/bnx2x/bnx2x_cmn.c of the component BPF. The manipulation
leads to memory leak (CVE-2022-3542).

A vulnerability, which was classified as problematic, has been found in
Linux Kernel. This issue affects the function unix_sock_destructor/
unix_release_sock of the file net/unix/af_unix.c of the component BPF.
The manipulation leads to memory leak (CVE-2022-3543).

A vulnerability classified as critical was found in Linux Kernel. Affected
by this vulnerability is the function l2cap_reassemble_sdu of the file
net/bluetooth/l2cap_core.c of the component Bluetooth. The manipulation
leads to use after free (CVE-2022-3564).

A vulnerability, which was classified as critical, has been found in Linux
Kernel. Affected by this issue is the function del_timer of the file
drivers/isdn/mISDN/l1oip_core.c of the component Bluetooth. The manipulation
leads to use after free (CVE-2022-3565).

A vulnerability was found in Linux Kernel. It has been declared as
problematic. Affected by this vulnerability is the function intr_callback
of the file drivers/net/usb/r8152.c of the component BPF. The manipulation
leads to logging of excessive data. The attack can be launched remotely
(CVE-2022-3594).

A vulnerability has been found in Linux Kernel and classified as
problematic. This vulnerability affects the function l2cap_recv_acldata
of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The
manipulation leads to memory leak (CVE-2022-3619).

A vulnerability was found in Linux Kernel. It has been declared as
problematic. Affected by this vulnerability is the function follow_page_pte
of the file mm/gup.c of the component BPF. The manipulation leads to race
condition (CVE-2022-3623).

An intra-object buffer overflow was found in brcmfmac, which can be
triggered by a malicious USB causing a Denial-of-Service (CVE-2022-3628).

drivers/video/fbdev/smscufx.c in the Linux kernel through 5.19.12 has ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-5.15.79-1.mga8", rpm:"kernel-desktop-5.15.79-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-5.15.79-1.mga8", rpm:"kernel-desktop-devel-5.15.79-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-5.15.79-1.mga8", rpm:"kernel-desktop586-5.15.79-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-5.15.79-1.mga8", rpm:"kernel-desktop586-devel-5.15.79-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-5.15.79-1.mga8", rpm:"kernel-server-5.15.79-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-5.15.79-1.mga8", rpm:"kernel-server-devel-5.15.79-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-5.15.79-1.mga8", rpm:"kernel-source-5.15.79-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~7.0.2~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~3.21~1.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf-devel", rpm:"lib64bpf-devel~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf0", rpm:"lib64bpf0~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf-devel", rpm:"libbpf-devel~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf0", rpm:"libbpf0~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~5.15.79~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.15.79-desktop-1.mga8", rpm:"virtualbox-kernel-5.15.79-desktop-1.mga8~7.0.2~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.15.79-server-1.mga8", rpm:"virtualbox-kernel-5.15.79-server-1.mga8~7.0.2~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~7.0.2~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~7.0.2~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.79-desktop-1.mga8", rpm:"xtables-addons-kernel-5.15.79-desktop-1.mga8~3.21~1.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.79-desktop586-1.mga8", rpm:"xtables-addons-kernel-5.15.79-desktop586-1.mga8~3.21~1.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.79-server-1.mga8", rpm:"xtables-addons-kernel-5.15.79-server-1.mga8~3.21~1.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~3.21~1.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~3.21~1.7.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~3.21~1.7.mga8", rls:"MAGEIA8"))) {
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
