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
  script_oid("1.3.6.1.4.1.25623.1.0.853166");
  script_version("2020-05-27T04:05:03+0000");
  script_cve_id("CVE-2019-18905");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-05-27 09:35:59 +0000 (Wed, 27 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-23 03:00:48 +0000 (Sat, 23 May 2020)");
  script_name("openSUSE: Security Advisory for autoyast2 (openSUSE-SU-2020:0676-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00050.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'autoyast2'
  package(s) announced via the openSUSE-SU-2020:0676-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for autoyast2 to version 4.1.15 fixes the following issues:

  Security issue fixed:

  - CVE-2019-18905: Removed all '--gpg-auto-import-keys' options from zypper
  commands (bsc#1140711).

  Non-security issue fixed:

  - Fix desktop files updating some icons and groups (bsc#1168123).

  - Restored some missing icons (bsc#1168123, bsc#1109310 and bsc#1168281).

  - Service for init scripts: Try to start 'network-online.target' before
  starting the autoyast init scripts in order to get a working network
  (bsc#1164105).

  - Always re-probe storage after pre-scripts (bsc#1170082, bsc#1133045).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-676=1");

  script_tag(name:"affected", value:"'autoyast2' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"autoyast2", rpm:"autoyast2~4.1.15~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autoyast2-installation", rpm:"autoyast2-installation~4.1.15~lp151.2.12.1", rls:"openSUSELeap15.1"))) {
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