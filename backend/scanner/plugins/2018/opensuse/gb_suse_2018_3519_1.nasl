###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3519_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for libgit2 openSUSE-SU-2018:3519-1 (libgit2)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852103");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2018-10887", "CVE-2018-10888", "CVE-2018-11235", "CVE-2018-15501", "CVE-2018-8099");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-27 06:25:10 +0200 (Sat, 27 Oct 2018)");
  script_name("SuSE Update for libgit2 openSUSE-SU-2018:3519-1 (libgit2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-10/msg00078.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgit2'
  package(s) announced via the openSUSE-SU-2018:3519_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libgit2 fixes the following issues:

  - CVE-2018-8099: Fixed possible denial of service attack via different
  vectors by not being able to differentiate between these status codes
  (bsc#1085256).

  - CVE-2018-11235: With a crafted .gitmodules file, a malicious project can
  execute an arbitrary script on a machine that runs 'git clone

  - -recurse-submodules' because submodule 'names' are obtained from this
  file, and then appended to $GIT_DIR/modules, leading to directory
  traversal with '../' in a name. Finally, post-checkout hooks from a
  submodule are executed, bypassing the intended design in which hooks are
  not obtained from a remote server.  (bsc#1095219)

  - CVE-2018-10887: It has been discovered that an unexpected sign extension
  in git_delta_apply function in delta.c file may have lead to an integer
  overflow which in turn leads to an out of bound read, allowing to read
  before the base object. An attacker could have used this flaw to leak
  memory addresses or cause a Denial of Service. (bsc#1100613)

  - CVE-2018-10888: A missing check in git_delta_apply function in delta.c
  file, may lead to an out-of-bound read while reading a binary delta
  file. An attacker may use this flaw to cause a Denial of Service.
  (bsc#1100612)

  - CVE-2018-15501: A remote attacker can send a crafted smart-protocol 'ng'
  packet that lacks a '\0' byte to trigger an out-of-bounds read that
  leads to DoS.  (bsc#1104641)

  This update was imported from the SUSE:SLE-12-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1314=1");

  script_tag(name:"affected", value:"libgit2 on openSUSE Leap 42.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"libgit2-24", rpm:"libgit2-24~0.24.1~10.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgit2-24-debuginfo", rpm:"libgit2-24-debuginfo~0.24.1~10.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgit2-debugsource", rpm:"libgit2-debugsource~0.24.1~10.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgit2-devel", rpm:"libgit2-devel~0.24.1~10.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgit2-24-32bit", rpm:"libgit2-24-32bit~0.24.1~10.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgit2-24-debuginfo-32bit", rpm:"libgit2-24-debuginfo-32bit~0.24.1~10.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
