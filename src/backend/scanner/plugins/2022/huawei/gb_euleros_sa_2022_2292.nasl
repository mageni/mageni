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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2292");
  script_cve_id("CVE-2020-36558", "CVE-2021-33655", "CVE-2021-33656", "CVE-2022-1789", "CVE-2022-20132", "CVE-2022-20154", "CVE-2022-20166", "CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21166", "CVE-2022-2153", "CVE-2022-26365", "CVE-2022-32296", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-34918");
  script_tag(name:"creation_date", value:"2022-09-14 04:42:02 +0000 (Wed, 14 Sep 2022)");
  script_version("2022-09-15T10:11:06+0000");
  script_tag(name:"last_modification", value:"2022-09-15 10:11:06 +0000 (Thu, 15 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-13 14:00:00 +0000 (Wed, 13 Jul 2022)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2022-2292)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2292");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2292");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2022-2292 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A race condition in the Linux kernel before 5.5.7 involving VT_RESIZEX could lead to a NULL pointer dereference and general protection fault.(CVE-2020-36558)

When sending malicous data to kernel by ioctl cmd FBIOPUT_VSCREENINFO,kernel will write memory out of bounds.(CVE-2021-33655)

When setting font with malicous data by ioctl cmd PIO_FONT,kernel will write memory out of bounds.(CVE-2021-33656)

An issue was discovered in the Linux kernel through 5.18.9. A type confusion bug in nft_set_elem_init (leading to a buffer overflow) could be used by a local attacker to escalate privileges, a different vulnerability than CVE-2022-32250. (The attacker can obtain root access, but must start with an unprivileged user namespace to obtain CAP_NET_ADMIN access.) This can be fixed in nft_setelem_parse_data in net/netfilter/nf_tables_api.c.(CVE-2022-34918)

In lock_sock_nested of sock.c, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-174846563References: Upstream kernel(CVE-2022-20154)

Incomplete cleanup in specific special register write operations for some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.(CVE-2022-21166)

Incomplete cleanup of microarchitectural fill buffers on some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.(CVE-2022-21125)

Incomplete cleanup of multi-core shared buffers for some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.(CVE-2022-21123)

Linux disk/nic frontends data leaks [This CNA information record relates to multiple CVEs, the text explains which aspects/vulnerabilities correspond to which CVE.] Linux Block and Network PV device frontends don't zero memory regions before sharing them with the backend (CVE-2022-26365, CVE-2022-33740). Additionally the granularity of the grant table doesn't allow sharing less than a 4K page, leading to unrelated data residing in the same 4K page as data shared with a backend being accessible by such backend (CVE-2022-33741, CVE-2022-33742).(CVE-2022-33742)

Linux disk/nic frontends data leaks [This CNA information record relates to multiple CVEs, the text explains which aspects/vulnerabilities correspond to which CVE.] Linux Block and Network PV device frontends don't zero memory regions before sharing them with the backend (CVE-2022-26365, CVE-2022-33740). Additionally the granularity of the grant table doesn't allow sharing less than a 4K page, leading to unrelated data residing in the same 4K page as data shared with a backend being accessible by such backend (CVE-2022-33741, CVE-2022-33742).(CVE-2022-33741)

Linux ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP9(x86_64).");

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

if(release == "EULEROS-2.0SP9-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.1.6.h806.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.1.6.h806.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.1.6.h806.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.1.6.h806.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
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
