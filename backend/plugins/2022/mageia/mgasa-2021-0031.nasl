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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0031");
  script_cve_id("CVE-2020-0423", "CVE-2020-0465", "CVE-2020-12912", "CVE-2020-14351", "CVE-2020-25656", "CVE-2020-25668", "CVE-2020-25669", "CVE-2020-25704", "CVE-2020-25705", "CVE-2020-27152", "CVE-2020-27194", "CVE-2020-27673", "CVE-2020-27675", "CVE-2020-27825", "CVE-2020-27830", "CVE-2020-27835", "CVE-2020-28588", "CVE-2020-28915", "CVE-2020-28941", "CVE-2020-28974", "CVE-2020-29534", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-8694");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-11 00:15:00 +0000 (Fri, 11 Dec 2020)");

  script_name("Mageia: Security Advisory (MGASA-2021-0031)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0031");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0031.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27939");
  script_xref(name:"URL", value:"https://kernelnewbies.org/Linux_5.8");
  script_xref(name:"URL", value:"https://kernelnewbies.org/Linux_5.9");
  script_xref(name:"URL", value:"https://kernelnewbies.org/Linux_5.10");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.1");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.2");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.3");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.4");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.5");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2021-0031 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides an upgrade to the new upstream 5.10 longterm branch,
currently based on 5.10.6, adding new features and new and improved
hardware support.

This update also fixes at least the following security issues:

In binder_release_work of binder.c, there is a possible use-after-free due
to improper locking. This could lead to local escalation of privilege in
the kernel with no additional execution privileges needed. User interaction
is not needed for exploitation (CVE-2020-0423).

In various methods of hid-multitouch.c, there is a possible out of bounds
write due to a missing bounds check. This could lead to local escalation of
privilege with no additional execution privileges needed. User interaction
is not needed for exploitation (CVE-2020-0465).

Insufficient access control in the Linux kernel driver for some Intel(R)
Processors may allow an authenticated user to potentially enable information
disclosure via local access (CVE-2020-8694).

A potential vulnerability in the AMD extension to Linux 'hwmon' service may
allow an attacker to use the Linux-based Running Average Power Limit (RAPL)
interface to show various side channel attacks. In line with industry
partners, AMD has updated the RAPL interface to require privileged access
(CVE-2020-12912).

A use-after-free memory flaw was found in the perf subsystem allowing a
local attacker with permission to monitor perf events to corrupt memory and
possibly escalate privileges. The highest threat from this vulnerability
is to data confidentiality and integrity as well as system availability
(CVE-2020-14351).

A use-after-free was found in the way the console subsystem was using ioctls
KDGKBSENT and KDSKBSENT. A local user could use this flaw to get read
memory access out of bounds. The highest threat from this vulnerability is
to data confidentiality (CVE-2020-25656).

Linux kernel concurrency use-after-free in vt (CVE-2020-25668).

Linux Kernel use-after-free in sunkbd_reinit (CVE-2020-25669).

A flaw memory leak in the Linux kernel performance monitoring subsystem was
found in the way if using PERF_EVENT_IOC_SET_FILTER. A local user could use
this flaw to starve the resources causing denial of service (CVE-2020-25704).

A flaw in the way reply ICMP packets are limited in the Linux kernel
functionality was found that allows to quickly scan open UDP ports. This
flaw allows an off-path remote user to effectively bypassing source port UDP
randomization. The highest threat from this vulnerability is to
confidentiality and possibly integrity, because software that relies on UDP
source port randomization are indirectly affected as well (CVE-2020-25705).

An issue was discovered in ioapic_lazy_update_eoi in arch/x86/kvm/ioapic.c
in the Linux kernel before 5.9.2. It has an infinite loop related to
improper interaction between a resampler and edge triggering (CVE-2020-27152).

An issue was discovered in the Linux kernel ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.10.6-1.mga7", rpm:"kernel-linus-5.10.6-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.10.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.10.6-1.mga7", rpm:"kernel-linus-devel-5.10.6-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.10.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.10.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.10.6~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.10.6-1.mga7", rpm:"kernel-linus-source-5.10.6-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.10.6~1.mga7", rls:"MAGEIA7"))) {
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
