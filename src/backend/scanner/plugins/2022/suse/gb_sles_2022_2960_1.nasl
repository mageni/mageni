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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2960.1");
  script_cve_id("CVE-2022-21233");
  script_tag(name:"creation_date", value:"2022-09-01 04:49:22 +0000 (Thu, 01 Sep 2022)");
  script_version("2022-09-01T10:11:07+0000");
  script_tag(name:"last_modification", value:"2022-09-01 10:11:07 +0000 (Thu, 01 Sep 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-24 18:48:00 +0000 (Wed, 24 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2960-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2960-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222960-1/");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-0");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/processors/xeon/scalable/xeon-scala");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2022:2960-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

Updated to Intel CPU Microcode 20220809 release (bsc#1201727):

CVE-2022-21233: Fixed an issue where stale data may have been leaked
 from the legacy xAPIC MMIO region, which could be used to compromise an
 SGX enclave (INTEL-SA-00657). See also:
[link moved to references]
 0657.html

Other fixes:

Update for functional issues. See also:
[link moved to references]
 ble-spec-update.html?wapkw=processor+specification+update

Updated Platforms:

 <pipe> Processor <pipe> Stepping <pipe> F-M-S/PI <pipe> Old Ver <pipe> New Ver <pipe>
Products
<pipe>:---------------<pipe>:---------<pipe>:------------<pipe>:---------<pipe>:---------<pipe>:---------
 <pipe> SKX-SP <pipe> B1 <pipe> 06-55-03/97 <pipe> 0100015d <pipe> 0100015e <pipe> Xeon Scalable <pipe> SKX-SP <pipe> H0/M0/U0 <pipe> 06-55-04/b7 <pipe> 02006d05 <pipe> 02006e05 <pipe>
Xeon Scalable <pipe> SKX-D <pipe> M1 <pipe> 06-55-04/b7 <pipe> 02006d05 <pipe>
02006e05 <pipe> Xeon D-21xx <pipe> ICX-SP <pipe> D0 <pipe> 06-6a-06/87 <pipe>
0d000363 <pipe> 0d000375 <pipe> Xeon Scalable Gen3 <pipe> GLK <pipe> B0 <pipe>
06-7a-01/01 <pipe> 0000003a <pipe> 0000003c <pipe> Pentium Silver N/J5xxx, Celeron N/J4xxx <pipe> GLK-R <pipe> R0 <pipe> 06-7a-08/01 <pipe> 0000001e <pipe> 00000020 <pipe>
Pentium J5040/N5030, Celeron J4125/J4025/N4020/N4120 <pipe> ICL-U/Y <pipe>
D1 <pipe> 06-7e-05/80 <pipe> 000000b0 <pipe> 000000b2 <pipe> Core Gen10 Mobile <pipe>
TGL-R <pipe> C0 <pipe> 06-8c-02/c2 <pipe> 00000026 <pipe> 00000028 <pipe> Core Gen11 Mobile <pipe> TGL-H <pipe> R0 <pipe> 06-8d-01/c2 <pipe> 0000003e <pipe> 00000040 <pipe>
Core Gen11 Mobile <pipe> RKL-S <pipe> B0 <pipe> 06-a7-01/02 <pipe> 00000053 <pipe>
00000054 <pipe> Core Gen11 <pipe> ADL <pipe> C0 <pipe> 06-97-02/03 <pipe> 0000001f
<pipe> 00000022 <pipe> Core Gen12 <pipe> ADL <pipe> C0 <pipe> 06-97-05/03 <pipe>
0000001f <pipe> 00000022 <pipe> Core Gen12 <pipe> ADL <pipe> L0 <pipe> 06-9a-03/80
<pipe> 0000041c <pipe> 00000421 <pipe> Core Gen12 <pipe> ADL <pipe> L0 <pipe>
06-9a-04/80 <pipe> 0000041c <pipe> 00000421 <pipe> Core Gen12 <pipe> ADL <pipe> C0
<pipe> 06-bf-02/03 <pipe> 0000001f <pipe> 00000022 <pipe> Core Gen12 <pipe> ADL <pipe>
C0 <pipe> 06-bf-05/03 <pipe> 0000001f <pipe> 00000022 <pipe> Core Gen12
 ------------------------------------------------------------------");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20220809~150200.18.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20220809~150200.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20220809~150200.18.1", rls:"SLES15.0SP2"))) {
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
