# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.883249");
  script_version("2020-06-12T07:11:22+0000");
  script_cve_id("CVE-2020-0543", "CVE-2020-0548", "CVE-2020-0549");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-06-12 09:20:35 +0000 (Fri, 12 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-11 03:01:11 +0000 (Thu, 11 Jun 2020)");
  script_name("CentOS: Security Advisory for microcode_ctl (CESA-2020:2432)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2020-June/035754.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode_ctl'
  package(s) announced via the CESA-2020:2432 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security Fix(es):

  * hw: Special Register Buffer Data Sampling (SRBDS) (CVE-2020-0543)

  * hw: L1D Cache Eviction Sampling (CVE-2020-0549)

  * hw: Vector Register Data Sampling (CVE-2020-0548)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * Update Intel CPU microcode to microcode-20200602 release, addresses:

  - Update of 06-2d-06/0x6d (SNB-E/EN/EP C1/M0) microcode from revision
0x61f
    up to 0x621,

  - Update of 06-2d-07/0x6d (SNB-E/EN/EP C2/M1) microcode from revision
0x718
    up to 0x71a,

  - Update of 06-3c-03/0x32 (HSW C0) microcode from revision 0x27 up to
0x28,

  - Update of 06-3d-04/0xc0 (BDW-U/Y E0/F0) microcode from revision 0x2e
    up to 0x2f,

  - Update of 06-45-01/0x72 (HSW-U C0/D0) microcode from revision 0x25
    up to 0x26,

  - Update of 06-46-01/0x32 (HSW-H C0) microcode from revision 0x1b up to
0x1c,

  - Update of 06-47-01/0x22 (BDW-H/Xeon E3 E0/G0) microcode from revision
0x21
    up to 0x22,

  - Update of 06-4e-03/0xc0 (SKL-U/Y D0) microcode from revision 0xd6
    up to 0xdc,

  - Update of 06-55-03/0x97 (SKX-SP B1) microcode from revision 0x1000151
    up to 0x1000157,

  - Update of 06-55-04/0xb7 (SKX-SP H0/M0/U0, SKX-D M1) microcode
    (in intel-06-55-04/intel-ucode/06-55-04) from revision 0x2000065
    up to 0x2006906,

  - Update of 06-55-06/0xbf (CLX-SP B0) microcode from revision 0x400002c
    up to 0x4002f01,

  - Update of 06-55-07/0xbf (CLX-SP B1) microcode from revision 0x500002c
    up to 0x5002f01,

  - Update of 06-5e-03/0x36 (SKL-H/S R0/N0) microcode from revision 0xd6
    up to 0xdc,

  - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from revision 0x46
    up to 0x78,

  - Update of 06-8e-09/0x10 (AML-Y22 H0) microcode from revision 0xca
    up to 0xd6,

  - Update of 06-8e-09/0xc0 (KBL-U/Y H0) microcode from revision 0xca
    up to 0xd6,

  - Update of 06-8e-0a/0xc0 (CFL-U43e D0) microcode from revision 0xca
    up to 0xd6,

  - Update of 06-8e-0b/0xd0 (WHL-U W0) microcode from revision 0xca
    up to 0xd6,

  - Update of 06-8e-0c/0x94 (AML-Y42 V0, CML-Y42 V0, WHL-U V0) microcode
    from revision 0xca up to 0xd6,

  - Update of 06-9e-09/0x2a (KBL-G/H/S/X/Xeon E3 B0) microcode from
revision
    0xca up to 0xd6,

  - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E3 U0) microcode from revision
0xca
    up to 0xd6,

  - Update of 06-9e-0b/0x02 (CFL-S B0) microcode from revision 0xca up to
0xd6,

  - Update of 06-9e-0c/0x22 (CFL-H/S P0) microcode from revision 0xca
    up to 0xd6,

  - Update of 06-9e-0d/0x22 (CFL-H R0) m ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'microcode_ctl' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"microcode_ctl", rpm:"microcode_ctl~2.1~61.6.el7_8", rls:"CentOS7"))) {
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