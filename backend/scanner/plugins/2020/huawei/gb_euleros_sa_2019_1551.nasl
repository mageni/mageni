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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1551");
  script_version("2020-01-23T12:12:38+0000");
  script_cve_id("CVE-2012-4424", "CVE-2013-0242", "CVE-2013-2207", "CVE-2013-4332", "CVE-2013-4458", "CVE-2014-8121", "CVE-2015-0235", "CVE-2015-1473", "CVE-2015-5180", "CVE-2015-7547", "CVE-2015-8777", "CVE-2015-8778", "CVE-2015-8779", "CVE-2016-3706", "CVE-2017-1000366", "CVE-2017-12132", "CVE-2017-15804", "CVE-2018-1000001", "CVE-2018-11236", "CVE-2018-6485");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 12:12:38 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:12:38 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for glibc (EulerOS-SA-2019-1551)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1551");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'glibc' package(s) announced via the EulerOS-SA-2019-1551 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"stdlib/canonicalize.c in the GNU C Library (aka glibc or libc6) 2.27 and earlier, when processing very long pathname arguments to the realpath function, could encounter an integer overflow on 32-bit architectures, leading to a stack-based buffer overflow and, potentially, arbitrary code execution.(CVE-2018-11236)

An integer overflow vulnerability was found in hcreate() and hcreate_r() functions which could result in an out-of-bounds memory access. This could lead to application crash or, potentially, arbitrary code execution.(CVE-2015-8778)

A stack-based buffer overflow was found in the way the libresolv library performed dual A/AAAA DNS queries. A remote attacker could create a specially crafted DNS response which could cause libresolv to crash or, potentially, execute code with the permissions of the user running the library. Note: this issue is only exposed when libresolv is called from the nss_dns NSS service module.(CVE-2015-7547)

A flaw was found in the regular expression matching routines that process multibyte character input. If an application utilized the glibc regular expression matching mechanism, an attacker could provide specially-crafted input that, when processed, would cause the application to crash.(CVE-2013-0242)

A flaw was found in the way memory was being allocated on the stack for user space binaries. If heap (or different memory region) and stack memory regions were adjacent to each other, an attacker could use this flaw to jump over the stack guard gap, cause controlled memory corruption on process stack or the adjacent memory region, and thus increase their privileges on the system. This is glibc-side mitigation which blocks processing of LD_LIBRARY_PATH for programs running in secure-execution mode and reduces the number of allocations performed by the processing of LD_AUDIT, LD_PRELOAD, and LD_HWCAP_MASK, making successful exploitation of this issue more difficult.(CVE-2017-1000366)

The DNS stub resolver in the GNU C Library (aka glibc or libc6) before version 2.26, when EDNS support is enabled, will solicit large UDP responses from name servers, potentially simplifying off-path DNS spoofing attacks due to IP fragmentation.(CVE-2017-12132)

It was found that the files back end of Name Service Switch (NSS) did not isolate iteration over an entire database from key-based look-up API calls. An application performing look-ups on a database while iterating over it could enter an infinite loop, leading to a denial of service.(CVE-2014-8121)

Stack-based buffer overflow in the getaddrinfo function in sysdeps/posix/getaddrinfo.c in the GNU C Library (ak ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'glibc' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.17~222.h11", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.17~222.h11", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.17~222.h11", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.17~222.h11", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.17~222.h11", rls:"EULEROSVIRT-3.0.1.0"))) {
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