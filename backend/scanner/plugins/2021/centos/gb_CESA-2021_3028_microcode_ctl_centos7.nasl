# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.883365");
  script_version("2021-08-24T12:01:48+0000");
  script_cve_id("CVE-2020-0543", "CVE-2020-0548", "CVE-2020-0549", "CVE-2020-8695", "CVE-2020-8696", "CVE-2020-8698", "CVE-2020-24489", "CVE-2020-24511", "CVE-2020-24512");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-25 10:27:37 +0000 (Wed, 25 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-01 18:46:00 +0000 (Thu, 01 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-08-10 03:01:09 +0000 (Tue, 10 Aug 2021)");
  script_name("CentOS: Security Advisory for microcode_ctl (CESA-2021:3028)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2021:3028");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2021-August/048347.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode_ctl'
  package(s) announced via the CESA-2021:3028 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The microcode_ctl packages provide microcode updates for Intel.

Security Fix(es):

  * hw: Special Register Buffer Data Sampling (SRBDS) (CVE-2020-0543)

  * hw: Vector Register Data Sampling (CVE-2020-0548)

  * hw: L1D Cache Eviction Sampling (CVE-2020-0549)

  * hw: vt-d related privilege escalation (CVE-2020-24489)

  * hw: improper isolation of shared resources in some Intel Processors
(CVE-2020-24511)

  * hw: observable timing discrepancy in some Intel Processors
(CVE-2020-24512)

  * hw: Information disclosure issue in Intel SGX via RAPL interface
(CVE-2020-8695)

  * hw: Vector Register Leakage-Active (CVE-2020-8696)

  * hw: Fast forward store predictor (CVE-2020-8698)");

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

  if(!isnull(res = isrpmvuln(pkg:"microcode_ctl", rpm:"microcode_ctl~2.1~73.11.el7_9", rls:"CentOS7"))) {
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