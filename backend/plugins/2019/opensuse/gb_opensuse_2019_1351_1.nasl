# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852481");
  script_version("2019-05-10T12:05:36+0000");
  script_cve_id("CVE-2018-19636", "CVE-2018-19637", "CVE-2018-19638", "CVE-2018-19639",
                "CVE-2018-19640");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-10 12:05:36 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-09 02:00:51 +0000 (Thu, 09 May 2019)");
  script_name("openSUSE Update for hostinfo, openSUSE-SU-2019:1351-1 (hostinfo, )");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00018.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hostinfo, '
  package(s) announced via the openSUSE-SU-2019:1351_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hostinfo, supportutils fixes the following issues:

  Security issues fixed for supportutils:

  - CVE-2018-19640: Fixed an issue where  users could kill arbitrary
  processes (bsc#1118463).

  - CVE-2018-19638: Fixed an issue where users could overwrite arbitrary log
  files (bsc#1118460).

  - CVE-2018-19639: Fixed a code execution if run with -v (bsc#1118462).

  - CVE-2018-19637: Fixed an issue where static temporary filename could
  allow overwriting of files (bsc#1117776).

  - CVE-2018-19636: Fixed a local root exploit via inclusion of attacker
  controlled shell script (bsc#1117751).

  Other issues fixed for supportutils:

  - Fixed invalid exit code commands (bsc#1125666)

  - SUSE separation in supportconfig (bsc#1125623)

  - Clarified supportconfig(8) -x option (bsc#1115245)

  - supportconfig: 3.0.127

  - btrfs filesystem usage

  - List products.d

  - Dump lsof errors

  - Added ha commands for corosync

  - Dumped find errors in ib_info

  Issues fixed in hostinfo:

  - Removed extra kernel install dates (bsc#1099498)

  - Resolved network bond issue (bsc#1054979)

  This update was imported from the SUSE:SLE-12:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1351=1");

  script_tag(name:"affected", value:"'hostinfo, ' package(s) on openSUSE Leap 42.3.");

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

if(release == "openSUSELeap42.3") {

  if(!isnull(res = isrpmvuln(pkg:"hostinfo", rpm:"hostinfo~1.0.1~21.3.1", rls:"openSUSELeap42.3"))) {
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
