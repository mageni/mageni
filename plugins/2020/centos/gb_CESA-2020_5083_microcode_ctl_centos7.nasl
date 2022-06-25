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
  script_oid("1.3.6.1.4.1.25623.1.0.883302");
  script_version("2020-11-27T03:36:52+0000");
  script_cve_id("CVE-2020-8695", "CVE-2020-8696", "CVE-2020-8698");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-11-27 10:33:34 +0000 (Fri, 27 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-20 04:01:17 +0000 (Fri, 20 Nov 2020)");
  script_name("CentOS: Security Advisory for microcode_ctl (CESA-2020:5083)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2020:5083");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2020-November/035872.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode_ctl'
  package(s) announced via the CESA-2020:5083 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security Fix(es):

  * hw: Information disclosure issue in Intel SGX via RAPL interface
(CVE-2020-8695)

  * hw: Vector Register Leakage-Active (CVE-2020-8696)

  * hw: Fast forward store predictor (CVE-2020-8698)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s)
listed in the References section.

Bug Fix(es) and Enhancement(s):

  * Update Intel CPU microcode to microcode-20201027 release, addresses:

  - Addition of 06-55-0b/0xbf (CPX-SP A1) microcode at revision 0x700001e,

  - Addition of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode at revision 0x68,

  - Addition of 06-a5-02/0x20 (CML-H R1) microcode at revision 0xe0,

  - Addition of 06-a5-03/0x22 (CML-S 6+2 G1) microcode at revision 0xe0,

  - Addition of 06-a5-05/0x22 (CML-S 10+2 Q0) microcode at revision 0xe0,

  - Addition of 06-a6-01/0x80 (CML-U 6+2 v2 K0) microcode at revision
    0xe0,

  - Update of 06-4e-03/0xc0 (SKL-U/U 2+3e/Y D0/K1) microcode (in
    intel-06-4e-03/intel-ucode/06-4e-03) from revision 0xdc up to 0xe2,

  - Update of 06-55-04/0xb7 (SKX-D/SP/W/X H0/M0/M1/U0) microcode (in
    intel-06-55-04/intel-ucode/06-55-04) from revision 0x2006906 up
    to 0x2006a08,

  - Update of 06-5e-03/0x36 (SKL-H/S/Xeon E3 N0/R0/S0) microcode (in
    intel-06-5e-03/intel-ucode/06-5e-03) from revision 0xdc up to 0xe2,

  - Update of 06-8e-09/0x10 (AML-Y 2+2 H0) microcode (in
    intel-06-8e-9e-0x-dell/intel-ucode/06-8e-09) from revision 0xd6 up
    to 0xde,

  - Update of 06-8e-09/0xc0 (KBL-U/U 2+3e/Y H0/J1) microcode (in
    intel-06-8e-9e-0x-dell/intel-ucode/06-8e-09) from revision 0xd6 up
    to 0xde,

  - Update of 06-8e-0a/0xc0 (CFL-U 4+3e D0, KBL-R Y0) microcode (in
    intel-06-8e-9e-0x-dell/intel-ucode/06-8e-0a) from revision 0xd6 up
    to 0xe0,

  - Update of 06-8e-0b/0xd0 (WHL-U W0) microcode (in
    intel-06-8e-9e-0x-dell/intel-ucode/06-8e-0b) from revision 0xd6 up
    to 0xde,

  - Update of 06-8e-0c/0x94 (AML-Y 4+2 V0, CML-U 4+2 V0, WHL-U V0)
    microcode (in intel-06-8e-9e-0x-dell/intel-ucode/06-8e-0c) from
    revision 0xd6 up to 0xde,

  - Update of 06-9e-09/0x2a (KBL-G/H/S/X/Xeon E3 B0) microcode (in
    intel-06-8e-9e-0x-dell/intel-ucode/06-9e-09) from revision 0xd6 up
    to 0xde,

  - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E U0) microcode (in
    intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0a) from revision 0xd6 up
    to 0xde,

  - Update of 06-9e-0b/0x02 (CFL-E/H/S B0) microcode (in
    intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0b) from revision 0xd6 up
    to 0xde,

  - Update of 06-9e-0c/0x22 (CFL-H/S/Xeon E P0) microcode (in
    intel-0 ...

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

  if(!isnull(res = isrpmvuln(pkg:"microcode_ctl", rpm:"microcode_ctl~2.1~73.2.el7_9", rls:"CentOS7"))) {
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