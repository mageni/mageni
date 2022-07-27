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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0333");
  script_cve_id("CVE-2019-18814", "CVE-2019-19462", "CVE-2020-0543", "CVE-2020-10732", "CVE-2020-10757", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-10781", "CVE-2020-15393", "CVE-2020-15780", "CVE-2020-15852");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-12 19:15:00 +0000 (Wed, 12 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0333)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0333");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0333.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27006");
  script_xref(name:"URL", value:"https://kernelnewbies.org/Linux_5.7");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2019-18814");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2019-19462");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-0543");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-10732");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-10757");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-10766");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-10767");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-10768");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-10781");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-15393");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-15780");
  script_xref(name:"URL", value:"https://www.linuxkernelcves.com/cves/CVE-2020-15852");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/CVE-2020-10766");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/CVE-2020-10767");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/CVE-2020-10768");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/CVE-2020-10781");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.7");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.7.1");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.7.2");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.7.3");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.7.4");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.7.5");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.7.6");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.7.7");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.7.8");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.7.9");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.7.10");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.7.11");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.7.12");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.7.13");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.7.14");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kmod-virtualbox, kmod-xtables-addons, xtables-addons' package(s) announced via the MGASA-2020-0333 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This provides an update to kernel 5.7 series, currently based on upstream
5.7.14 adding support for new hardware and features, and fixes at least the
following security issues:

An issue was discovered in the Linux kernel through 5.3.9. There is a
use-after-free when aa_label_parse() fails in aa_audit_rule_init() in
security/apparmor/audit.c (CVE-2019-18814).

relay_open in kernel/relay.c in the Linux kernel through 5.4.1 allows local
users to cause a denial of service (such as relay blockage) by triggering a
NULL alloc_percpu result (CVE-2019-19462).

Incomplete cleanup from specific special register read operations in some
Intel(R) Processors may allow an authenticated user to potentially enable
information disclosure via local access (CVE-2020-0543).

A flaw was found in the Linux kernel's implementation of Userspace core dumps.
This flaw allows an attacker with a local account to crash a trivial program
and exfiltrate private kernel data (CVE-2020-10732).

A flaw was found in the Linux Kernel in versions after 4.5-rc1 in the way
mremap handled DAX Huge Pages. This flaw allows a local attacker with access
to a DAX enabled storage to escalate their privileges on the system
(CVE-2020-10757).

A logic bug flaw was found in the Linux kernel's implementation of SSBD. A
bug in the logic handling allows an attacker with a local account to disable
SSBD protection during a context switch when additional speculative execution
mitigations are in place. This issue was introduced when the per task/process
conditional STIPB switching was added on top of the existing SSBD switching.
The highest threat from this vulnerability is to confidentiality
(CVE-2020-10766).

A flaw was found in the Linux kernel's implementation of the Enhanced IBPB
(Indirect Branch Prediction Barrier). The IBPB mitigation will be disabled
when STIBP is not available or when the Enhanced Indirect Branch Restricted
Speculation (IBRS) is available. This flaw allows a local attacker to perform
a Spectre V2 style attack when this configuration is active. The highest
threat from this vulnerability is to confidentiality (CVE-2020-10767).

A flaw was found in the prctl() function, where it can be used to enable
indirect branch speculation after it has been disabled. This call incorrectly
reports it as being 'force disabled' when it is not and opens the system to
Spectre v2 attacks. The highest threat from this vulnerability is to
confidentiality (CVE-2020-10768).

A flaw was found in the ZRAM kernel module, where a user with a local account
and the ability to read the /sys/class/zram-control/hot_add file can create
ZRAM device nodes in the /dev/ directory. This read allocates kernel memory
and is not accounted for a user that triggers the creation of that ZRAM
device. With this vulnerability, continually reading the device may consume a
large amount of system memory and cause the Out-of-Memory (OOM) killer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, kmod-virtualbox, kmod-xtables-addons, xtables-addons' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-xtables-addons", rpm:"dkms-xtables-addons~3.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iptaccount", rpm:"iptaccount~3.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-5.7.14-1.mga7", rpm:"kernel-desktop-5.7.14-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-5.7.14-1.mga7", rpm:"kernel-desktop-devel-5.7.14-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-5.7.14-1.mga7", rpm:"kernel-desktop586-5.7.14-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-5.7.14-1.mga7", rpm:"kernel-desktop586-devel-5.7.14-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-5.7.14-1.mga7", rpm:"kernel-server-5.7.14-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-5.7.14-1.mga7", rpm:"kernel-server-devel-5.7.14-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-5.7.14-1.mga7", rpm:"kernel-source-5.7.14-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~6.0.24~4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~3.10~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64account-devel", rpm:"lib64account-devel~3.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64account0", rpm:"lib64account0~3.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf-devel", rpm:"lib64bpf-devel~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf0", rpm:"lib64bpf0~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaccount-devel", rpm:"libaccount-devel~3.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaccount0", rpm:"libaccount0~3.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf-devel", rpm:"libbpf-devel~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf0", rpm:"libbpf0~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~5.7.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.7.14-desktop-1.mga7", rpm:"virtualbox-kernel-5.7.14-desktop-1.mga7~6.0.24~4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.7.14-desktop586-1.mga7", rpm:"virtualbox-kernel-5.7.14-desktop586-1.mga7~6.0.24~4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.7.14-server-1.mga7", rpm:"virtualbox-kernel-5.7.14-server-1.mga7~6.0.24~4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~6.0.24~4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~6.0.24~4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~6.0.24~4.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons", rpm:"xtables-addons~3.10~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.7.14-desktop-1.mga7", rpm:"xtables-addons-kernel-5.7.14-desktop-1.mga7~3.10~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.7.14-desktop586-1.mga7", rpm:"xtables-addons-kernel-5.7.14-desktop586-1.mga7~3.10~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.7.14-server-1.mga7", rpm:"xtables-addons-kernel-5.7.14-server-1.mga7~3.10~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~3.10~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~3.10~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~3.10~2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-geoip", rpm:"xtables-geoip~3.10~1.mga7", rls:"MAGEIA7"))) {
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
