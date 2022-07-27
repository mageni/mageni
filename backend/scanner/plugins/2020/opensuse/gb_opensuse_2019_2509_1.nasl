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
  script_oid("1.3.6.1.4.1.25623.1.0.852919");
  script_version("2020-01-16T07:19:44+0000");
  script_cve_id("CVE-2019-11135", "CVE-2019-11139");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-01-16 07:19:44 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 09:45:53 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE Update for ucode-intel openSUSE-SU-2019:2509-1 (ucode-intel)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00036.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel'
  package(s) announced via the openSUSE-SU-2019:2509_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

  - Updated to 20191112 security release (bsc#1155988)

  - Processor             Identifier     Version       Products

  - Model        Stepping F-MO-S/PI      Old->New

  - ---- new platforms ----------------------------------------

  - CML-U62      A0       6-a6-0/80           000000c6 Core Gen10 Mobile

  - CNL-U        D0       6-66-3/80           0000002a Core Gen8 Mobile

  - SKX-SP       B1       6-55-3/97           01000150 Xeon Scalable

  - ICL U/Y      D1       6-7e-5/80           00000046 Core Gen10 Mobile

  - ---- updated platforms ------------------------------------

  - SKL U/Y      D0       6-4e-3/c0 000000cc->000000d4 Core Gen6 Mobile

  - SKL H/S/E3   R0/N0    6-5e-3/36 000000cc->000000d4 Core Gen6

  - AML-Y22      H0       6-8e-9/10 000000b4->000000c6 Core Gen8 Mobile

  - KBL-U/Y      H0       6-8e-9/c0 000000b4->000000c6 Core Gen7 Mobile

  - CFL-U43e     D0       6-8e-a/c0 000000b4->000000c6 Core Gen8 Mobile

  - WHL-U        W0       6-8e-b/d0 000000b8->000000c6 Core Gen8 Mobile

  - AML-Y        V0       6-8e-c/94 000000b8->000000c6 Core Gen10 Mobile

  - CML-U42      V0       6-8e-c/94 000000b8->000000c6 Core Gen10 Mobile

  - WHL-U        V0       6-8e-c/94 000000b8->000000c6 Core Gen8 Mobile

  - KBL-G/X      H0       6-9e-9/2a 000000b4->000000c6 Core Gen7/Gen8

  - KBL-H/S/E3   B0       6-9e-9/2a 000000b4->000000c6 Core Gen7, Xeon E3
  v6

  - CFL-H/S/E3   U0       6-9e-a/22 000000b4->000000c6 Core Gen8 Desktop,
  Mobile, Xeon E

  - CFL-S        B0       6-9e-b/02 000000b4->000000c6 Core Gen8

  - CFL-H        R0       6-9e-d/22 000000b8->000000c6 Core Gen9 Mobile

  - Includes security fixes for:

  - CVE-2019-11135: Added feature allowing to disable TSX RTM (bsc#1139073)

  - CVE-2019-11139: A CPU microcode only fix for Voltage modulation issues
  (bsc#1141035)

  This update was imported from the SUSE:SLE-15-SP1:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2509=1");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20191112~lp151.2.9.1", rls:"openSUSELeap15.1"))) {
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
