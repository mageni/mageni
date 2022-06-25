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
  script_oid("1.3.6.1.4.1.25623.1.0.854263");
  script_version("2021-11-29T04:48:32+0000");
  script_cve_id("CVE-2021-39139", "CVE-2021-39140", "CVE-2021-39141", "CVE-2021-39144", "CVE-2021-39145", "CVE-2021-39146", "CVE-2021-39147", "CVE-2021-39148", "CVE-2021-39149", "CVE-2021-39150", "CVE-2021-39151", "CVE-2021-39152", "CVE-2021-39153", "CVE-2021-39154");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-11-29 10:38:15 +0000 (Mon, 29 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-01 02:03:20 +0000 (Mon, 01 Nov 2021)");
  script_name("openSUSE: Security Advisory for xstream (openSUSE-SU-2021:1401-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1401-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PVLPNQBYDFG66KQSVPOIZDRX3AQEQYGU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xstream'
  package(s) announced via the openSUSE-SU-2021:1401-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xstream fixes the following issues:

  - Upgrade to 1.4.18

  - CVE-2021-39139: Fixed an issue that allowed an attacker to execute
       arbitrary code execution by manipulating the processed input stream with
       type information. (bsc#1189798)

  - CVE-2021-39140: Fixed an issue that allowed an attacker to execute a DoS
       attack by manipulating the processed input stream. (bsc#1189798)

  - CVE-2021-39141: Fixed an issue that allowed an attacker to achieve
       arbitrary code execution. (bsc#1189798)

  - CVE-2021-39144: Fixed an issue that allowed an attacker to achieve
       arbitrary code execution. (bsc#1189798)

  - CVE-2021-39145: Fixed an issue that allowed an attacker to achieve
       arbitrary code execution. (bsc#1189798)

  - CVE-2021-39146: Fixed an issue that allowed an attacker to achieve
       arbitrary code execution. (bsc#1189798)

  - CVE-2021-39147: Fixed an issue that allowed an attacker to achieve
       arbitrary code execution. (bsc#1189798)

  - CVE-2021-39148: Fixed an issue that allowed an attacker to achieve
       arbitrary code execution. (bsc#1189798)

  - CVE-2021-39149: Fixed an issue that allowed an attacker to achieve
       arbitrary code execution. (bsc#1189798)

  - CVE-2021-39150: Fixed an issue that allowed an attacker to access
       protected resources hosted within the intranet or in the host itself.
       (bsc#1189798)

  - CVE-2021-39151: Fixed an issue that allowed an attacker to achieve
       arbitrary code execution. (bsc#1189798)

  - CVE-2021-39152: Fixed an issue that allowed an attacker to access
       protected resources hosted within the intranet or in the host itself.
       (bsc#1189798)

  - CVE-2021-39153: Fixed an issue that allowed an attacker to achieve
       arbitrary code execution. (bsc#1189798)

  - CVE-2021-39154: Fixed an issue that allowed an attacker to achieve
       arbitrary code execution. (bsc#1189798)

     This update was imported from the SUSE:SLE-15-SP2:Update update project.");

  script_tag(name:"affected", value:"'xstream' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"xstream", rpm:"xstream~1.4.18~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xstream-benchmark", rpm:"xstream-benchmark~1.4.18~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xstream-javadoc", rpm:"xstream-javadoc~1.4.18~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xstream-parent", rpm:"xstream-parent~1.4.18~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
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