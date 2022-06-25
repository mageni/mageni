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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1412");
  script_version("2020-01-23T11:25:13+0000");
  script_cve_id("CVE-2018-15908", "CVE-2018-15909", "CVE-2018-15911", "CVE-2018-16511", "CVE-2018-16539", "CVE-2018-16541", "CVE-2018-16802", "CVE-2018-16863", "CVE-2018-17183", "CVE-2018-17961", "CVE-2018-18073", "CVE-2018-18284", "CVE-2018-19134", "CVE-2018-19409");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 11:25:13 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:25:13 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for ghostscript (EulerOS-SA-2018-1412)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-2\.5\.2");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1412");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'ghostscript' package(s) announced via the EulerOS-SA-2018-1412 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the ghostscript .tempfile function did not properly handle file permissions. An attacker could possibly exploit this to exploit this to bypass the -dSAFER protection and delete files or disclose their content via a specially crafted PostScript document.CVE-2018-15908

It was discovered that the ghostscript .shfill operator did not properly validate certain types. An attacker could possibly exploit this to bypass the -dSAFER protection and crash ghostscript or, possibly, execute arbitrary code in the ghostscript context via a specially crafted PostScript document.CVE-2018-15909

It was discovered that ghostscript did not properly verify the key used in aesdecode. An attacker could possibly exploit this to bypass the -dSAFER protection and crash ghostscript or, possibly, execute arbitrary code in the ghostscript context via a specially crafted PostScript document.CVE-2018-15911

It was discovered that the ghostscript .type operator did not properly validate its operands. A specially crafted PostScript document could exploit this to crash ghostscript or, possibly, execute arbitrary code in the context of the ghostscript process.CVE-2018-16511

It was discovered that the ghostscript did not properly restrict access to files open prior to enabling the -dSAFER mode. An attacker could possibly exploit this to bypass the -dSAFER protection and disclose the content of affected files via a specially crafted PostScript document.CVE-2018-16539

It was discovered that the ghostscript device cleanup did not properly handle devices replaced with a null device. An attacker could possibly exploit this to bypass the -dSAFER protection and crash ghostscript or, possibly, execute arbitrary code in the ghostscript context via a specially crafted PostScript document.CVE-2018-16541

An issue was discovered in Artifex Ghostscript before 9.25. Incorrect 'restoration of privilege' checking when running out of stack during exception handling could be used by attackers able to supply crafted PostScript to execute code using the 'pipe' instruction. This is due to an incomplete fix for CVE-2018-16509.CVE-2018-16802

It was found that RHSA-2018:2918 did not fully fix CVE-2018-16509. An attacker could possibly exploit another variant of the flaw and bypass the -dSAFER protection to, for example, execute arbitrary shell commands via a specially crafted PostScript document.CVE-2018-16863

Artifex Ghostscript before 9.25 allowed a user-writable error exception table, which could be used by remote attackers able to supply crafted PostScript to potentially overwrite or replace error han ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Huawei EulerOS Virtualization 2.5.2.");

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

if(release == "EULEROSVIRT-2.5.2") {

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.07~31.6.h1", rls:"EULEROSVIRT-2.5.2"))) {
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