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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3476.1");
  script_cve_id("CVE-2021-39139", "CVE-2021-39140", "CVE-2021-39141", "CVE-2021-39144", "CVE-2021-39145", "CVE-2021-39146", "CVE-2021-39147", "CVE-2021-39148", "CVE-2021-39149", "CVE-2021-39150", "CVE-2021-39151", "CVE-2021-39152", "CVE-2021-39153", "CVE-2021-39154");
  script_tag(name:"creation_date", value:"2021-10-21 06:38:29 +0000 (Thu, 21 Oct 2021)");
  script_version("2021-10-21T06:38:29+0000");
  script_tag(name:"last_modification", value:"2021-10-22 10:34:07 +0000 (Fri, 22 Oct 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-26 20:43:00 +0000 (Thu, 26 Aug 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3476-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3476-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213476-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xstream' package(s) announced via the SUSE-SU-2021:3476-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xstream fixes the following issues:

Upgrade to 1.4.18

CVE-2021-39139: Fixed an issue that allowed an attacker to execute
 arbitrary code execution by manipulating the processed input stream with
 type information. (bsc#1189798)

CVE-2021-39140: Fixed an issue that allowed an attacker to execute a DoS
 attack by manipulating the processed input stream. (bsc#1189798)

CVE-2021-39141: Fixed an issue that allowed an attacker to achieve
 arbitrary code execution. (bsc#1189798)

CVE-2021-39144: Fixed an issue that allowed an attacker to achieve
 arbitrary code execution. (bsc#1189798)

CVE-2021-39145: Fixed an issue that allowed an attacker to achieve
 arbitrary code execution. (bsc#1189798)

CVE-2021-39146: Fixed an issue that allowed an attacker to achieve
 arbitrary code execution. (bsc#1189798)

CVE-2021-39147: Fixed an issue that allowed an attacker to achieve
 arbitrary code execution. (bsc#1189798)

CVE-2021-39148: Fixed an issue that allowed an attacker to achieve
 arbitrary code execution. (bsc#1189798)

CVE-2021-39149: Fixed an issue that allowed an attacker to achieve
 arbitrary code execution. (bsc#1189798)

CVE-2021-39150: Fixed an issue that allowed an attacker to access
 protected resources hosted within the intranet or in the host itself.
 (bsc#1189798)

CVE-2021-39151: Fixed an issue that allowed an attacker to achieve
 arbitrary code execution. (bsc#1189798)

CVE-2021-39152: Fixed an issue that allowed an attacker to access
 protected resources hosted within the intranet or in the host itself.
 (bsc#1189798)

CVE-2021-39153: Fixed an issue that allowed an attacker to achieve
 arbitrary code execution. (bsc#1189798)

CVE-2021-39154: Fixed an issue that allowed an attacker to achieve
 arbitrary code execution. (bsc#1189798)");

  script_tag(name:"affected", value:"'xstream' package(s) on SUSE Linux Enterprise Module for Development Tools 15-SP2, SUSE Linux Enterprise Module for Development Tools 15-SP3, SUSE Linux Enterprise Module for SUSE Manager Server 4.1, SUSE Linux Enterprise Module for SUSE Manager Server 4.2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"xstream", rpm:"xstream~1.4.18~3.14.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"xstream", rpm:"xstream~1.4.18~3.14.1", rls:"SLES15.0SP3"))) {
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
