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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1532");
  script_version("2020-01-23T12:06:52+0000");
  script_cve_id("CVE-2013-2894", "CVE-2013-2930", "CVE-2014-4652", "CVE-2014-8133", "CVE-2014-9644", "CVE-2015-6526", "CVE-2015-8215", "CVE-2016-4470", "CVE-2016-4565", "CVE-2016-4913", "CVE-2016-6198", "CVE-2016-7097", "CVE-2017-15274", "CVE-2017-16995", "CVE-2017-17864", "CVE-2017-6001", "CVE-2018-14610", "CVE-2018-7757", "CVE-2019-5489", "CVE-2019-9162");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 12:06:52 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:06:52 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1532)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1532");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'kernel' package(s) announced via the EulerOS-SA-2019-1532 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way the Linux kernel's perf subsystem retrieved userlevel stack traces on PowerPC systems. A local, unprivileged user could use this flaw to cause a denial of service on the system by creating a special stack layout that would force the perf_callchain_user_64() function into an infinite loop.(CVE-2015-6526

A vulnerability was found in the Linux kernel. Payloads of NM entries are not supposed to contain NUL. When such entry is processed, only the part prior to the first NUL goes into the concatenation (i.e. the directory entry name being encoded by a bunch of NM entries). The process stops when the amount collected so far + the claimed amount in the current NM entry exceed 254. However, the value returned as the total length is the sum of *claimed* sizes, not the actual amount collected. And that's what will be passed to readdir() callback as the name length - 8Kb __copy_to_user() from a buffer allocated by __get_free_page().(CVE-2016-4913

The perf_trace_event_perm function in kernel/trace/trace_event_perf.c in the Linux kernel before 3.12.2 does not properly restrict access to the perf subsystem, which allows local users to enable function tracing via a crafted application.(CVE-2013-2930

The mincore() implementation in mm/mincore.c in the Linux kernel through 4.19.13 allowed local attackers to observe page cache access patterns of other processes on the same system, potentially allowing sniffing of secret information. (Fixing this affects the output of the fincore program.) Limited remote exploitation may be possible, as demonstrated by latency differences in accessing public files from an Apache HTTP Server.(CVE-2019-5489

It was found that the espfix functionality could be bypassed by installing a 16-bit RW data segment into GDT instead of LDT (which espfix checks), and using that segment on the stack. A local, unprivileged user could potentially use this flaw to leak kernel stack addresses.(CVE-2014-8133

An issue was discovered in the btrfs filesystem code in the Linux kernel. An out-of-bounds access is possible in write_extent_buffer() when mounting and operating a crafted btrfs image due to a lack of verification at mount time within the btrfs_read_block_groups() in fs/btrfs/extent-tree.c function. This could lead to a system crash and a denial of service.(CVE-2018-14610

kernel/bpf/verifier.c in the Linux kernel through 4.14.8 mishandles states_equal comparisons between the pointer data type and the UNKNOWN_VALUE data type, which allows local users to obtain potentially sensitive address information, aka a 'pointer leak.'(CVE-2017- ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.1.0.");

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

if(release == "EULEROSVIRTARM64-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
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