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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2290.1");
  script_cve_id("CVE-2022-33972");
  script_tag(name:"creation_date", value:"2023-05-25 04:21:38 +0000 (Thu, 25 May 2023)");
  script_version("2023-05-25T09:08:46+0000");
  script_tag(name:"last_modification", value:"2023-05-25 09:08:46 +0000 (Thu, 25 May 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-06 19:43:00 +0000 (Mon, 06 Mar 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2290-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2290-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232290-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel' package(s) announced via the SUSE-SU-2023:2290-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

Updated to Intel CPU Microcode 20230512 release. (bsc#1211382)
New Platforms
 <pipe> Processor <pipe> Stepping <pipe> F-M-S/PI <pipe> Old Ver <pipe> New Ver <pipe> Products
 <pipe>:---------------<pipe>:---------<pipe>:------------<pipe>:---------<pipe>:---------<pipe>:---------
 <pipe> ADL-N <pipe> A0 <pipe> 06-be-00/01 <pipe> <pipe> 00000010 <pipe> Core i3-N305/N300, N50/N97/N100/N200, Atom x7211E/x7213E/x7425E
 <pipe> AZB <pipe> A0 <pipe> 06-9a-04/40 <pipe> <pipe> 00000004 <pipe> Intel(R) Atom(R) C1100
 <pipe> AZB <pipe> R0 <pipe> 06-9a-04/40 <pipe> <pipe> 00000004 <pipe> Intel(R) Atom(R) C1100 Updated Platforms
 <pipe> Processor <pipe> Stepping <pipe> F-M-S/PI <pipe> Old Ver <pipe> New Ver <pipe> Products
 <pipe>:---------------<pipe>:---------<pipe>:------------<pipe>:---------<pipe>:---------<pipe>:---------
 <pipe> ADL <pipe> L0 <pipe> 06-9a-03/80 <pipe> 00000429 <pipe> 0000042a <pipe> Core Gen12
 <pipe> ADL <pipe> L0 <pipe> 06-9a-04/80 <pipe> 00000429 <pipe> 0000042a <pipe> Core Gen12
 <pipe> AML-Y22 <pipe> H0 <pipe> 06-8e-09/10 <pipe> <pipe> 000000f2 <pipe> Core Gen8 Mobile
 <pipe> AML-Y42 <pipe> V0 <pipe> 06-8e-0c/94 <pipe> 000000f4 <pipe> 000000f6 <pipe> Core Gen10 Mobile
 <pipe> CFL-H <pipe> R0 <pipe> 06-9e-0d/22 <pipe> 000000f4 <pipe> 000000f8 <pipe> Core Gen9 Mobile
 <pipe> CFL-H/S <pipe> P0 <pipe> 06-9e-0c/22 <pipe> 000000f0 <pipe> 000000f2 <pipe> Core Gen9
 <pipe> CFL-H/S/E3 <pipe> U0 <pipe> 06-9e-0a/22 <pipe> 000000f0 <pipe> 000000f2 <pipe> Core Gen8 Desktop, Mobile, Xeon E
 <pipe> CFL-S <pipe> B0 <pipe> 06-9e-0b/02 <pipe> 000000f0 <pipe> 000000f2 <pipe> Core Gen8
 <pipe> CFL-U43e <pipe> D0 <pipe> 06-8e-0a/c0 <pipe> 000000f0 <pipe> 000000f2 <pipe> Core Gen8 Mobile
 <pipe> CLX-SP <pipe> B0 <pipe> 06-55-06/bf <pipe> 04003303 <pipe> 04003501 <pipe> Xeon Scalable Gen2
 <pipe> CLX-SP <pipe> B1 <pipe> 06-55-07/bf <pipe> 05003303 <pipe> 05003501 <pipe> Xeon Scalable Gen2
 <pipe> CML-H <pipe> R1 <pipe> 06-a5-02/20 <pipe> 000000f4 <pipe> 000000f6 <pipe> Core Gen10 Mobile
 <pipe> CML-S102 <pipe> Q0 <pipe> 06-a5-05/22 <pipe> 000000f4 <pipe> 000000f6 <pipe> Core Gen10
 <pipe> CML-S62 <pipe> G1 <pipe> 06-a5-03/22 <pipe> 000000f4 <pipe> 000000f6 <pipe> Core Gen10
 <pipe> CML-U62 V1 <pipe> A0 <pipe> 06-a6-00/80 <pipe> 000000f4 <pipe> 000000f6 <pipe> Core Gen10 Mobile
 <pipe> CML-U62 V2 <pipe> K1 <pipe> 06-a6-01/80 <pipe> 000000f4 <pipe> 000000f6 <pipe> Core Gen10 Mobile
 <pipe> CML-Y42 <pipe> V0 <pipe> 06-8e-0c/94 <pipe> 000000f4 <pipe> 000000f6 <pipe> Core Gen10 Mobile
 <pipe> CPX-SP <pipe> A1 <pipe> 06-55-0b/bf <pipe> 07002503 <pipe> 07002601 <pipe> Xeon Scalable Gen3
 <pipe> ICL-D <pipe> B0 <pipe> 06-6c-01/10 <pipe> 01000211 <pipe> 01000230 <pipe> Xeon D-17xx, D-27xx
 <pipe> ICL-U/Y <pipe> D1 <pipe> 06-7e-05/80 <pipe> 000000b8 <pipe> 000000ba <pipe> Core Gen10 Mobile
 <pipe> ICX-SP <pipe> D0 <pipe> 06-6a-06/87 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20230512~13.107.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-debuginfo", rpm:"ucode-intel-debuginfo~20230512~13.107.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-debugsource", rpm:"ucode-intel-debugsource~20230512~13.107.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20230512~13.107.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-debuginfo", rpm:"ucode-intel-debuginfo~20230512~13.107.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-debugsource", rpm:"ucode-intel-debugsource~20230512~13.107.1", rls:"SLES12.0SP4"))) {
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
