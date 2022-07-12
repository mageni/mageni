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
  script_oid("1.3.6.1.4.1.25623.1.0.853868");
  script_version("2021-06-17T06:11:17+0000");
  script_cve_id("CVE-2020-24489", "CVE-2020-24511", "CVE-2020-24512", "CVE-2020-24513");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-06-17 10:43:15 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-17 03:01:48 +0000 (Thu, 17 Jun 2021)");
  script_name("openSUSE: Security Advisory for ucode-intel (openSUSE-SU-2021:0876-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0876-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LVSPIXHZZESTI3IJTF7URWDUHHXIRWBP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode-intel'
  package(s) announced via the openSUSE-SU-2021:0876-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

     Updated to Intel CPU Microcode 20210608 release.

  - CVE-2020-24513: A domain bypass transient execution vulnerability was
         discovered on some Intel Atom processors that use a
         micro-architectural incident channel. (INTEL-SA-00465 bsc#1179833)

  - CVE-2020-24511: The IBRS feature to mitigate Spectre variant 2
         transient execution side channel vulnerabilities may not fully prevent
         non-root (guest) branches from controlling the branch predictions of
         the root (host) (INTEL-SA-00464 bsc#1179836)

  - CVE-2020-24512: Fixed trivial data value cache-lines such as all-zero
         value cache-lines may lead to changes in cache-allocation or
         write-back behavior for such cache-lines (bsc#1179837 INTEL-SA-00464)

  - CVE-2020-24489: Fixed Intel VT-d device pass through potential local
         privilege escalation (INTEL-SA-00442 bsc#1179839)

     Other fixes:

  - Update for functional issues. Refer to [Third Generation Intel Xeon

  - Update for functional issues. Refer to [Second Generation Intel Xeon

  - Update for functional issues. Refer to [Intel Xeon Processor Scalable
  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'ucode-intel' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel", rpm:"ucode-intel~20210525~lp152.2.17.1", rls:"openSUSELeap15.2"))) {
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
