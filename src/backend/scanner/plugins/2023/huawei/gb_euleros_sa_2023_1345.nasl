# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1345");
  script_cve_id("CVE-2022-3566", "CVE-2022-3629");
  script_tag(name:"creation_date", value:"2023-02-09 04:29:52 +0000 (Thu, 09 Feb 2023)");
  script_version("2023-02-09T10:17:23+0000");
  script_tag(name:"last_modification", value:"2023-02-09 10:17:23 +0000 (Thu, 09 Feb 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-20 12:50:00 +0000 (Thu, 20 Oct 2022)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2023-1345)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1345");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1345");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2023-1345 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability, which was classified as problematic, was found in Linux Kernel. This affects the function tcp_getsockopt/tcp_setsockopt of the component TCP Handler. The manipulation leads to race condition. It is recommended to apply a patch to fix this issue. The identifier VDB-211089 was assigned to this vulnerability.(CVE-2022-3566)

A vulnerability was found in Linux Kernel. It has been declared as problematic. This vulnerability affects the function vsock_connect of the file net/vmw_vsock/af_vsock.c of the component IPsec. The manipulation leads to memory leak. It is recommended to apply a patch to fix this issue. VDB-211930 is the identifier assigned to this vulnerability.(CVE-2022-3629)");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~4.19.36~vhulk1907.1.0.h1350.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.36~vhulk1907.1.0.h1350.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.36~vhulk1907.1.0.h1350.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.36~vhulk1907.1.0.h1350.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.36~vhulk1907.1.0.h1350.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.36~vhulk1907.1.0.h1350.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.36~vhulk1907.1.0.h1350.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.36~vhulk1907.1.0.h1350.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.36~vhulk1907.1.0.h1350.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
