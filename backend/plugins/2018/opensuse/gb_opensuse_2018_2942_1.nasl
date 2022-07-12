###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2942_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for mgetty openSUSE-SU-2018:2942-1 (mgetty)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852064");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2018-16741", "CVE-2018-16742", "CVE-2018-16743", "CVE-2018-16744", "CVE-2018-16745");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:40:40 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for mgetty openSUSE-SU-2018:2942-1 (mgetty)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-09/msg00085.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mgetty'
  package(s) announced via the openSUSE-SU-2018:2942_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mgetty fixes the following issues:

  - CVE-2018-16741: The function do_activate() did not properly sanitize
  shell metacharacters to prevent command injection (bsc#1108752).

  - CVE-2018-16745: The mail_to parameter was not sanitized, leading to a
  buffer
  overflow if long untrusted input reached it (bsc#1108756).

  - CVE-2018-16744: The mail_to parameter was not sanitized, leading to
  command injection if untrusted input reached reach it (bsc#1108757).

  - CVE-2018-16742: Prevent stack-based buffer overflow that could have been
  triggered via a command-line parameter (bsc#1108762).

  - CVE-2018-16743: The command-line parameter username wsa passed
  unsanitized to strcpy(), which could have caused a stack-based buffer
  overflow (bsc#1108761).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1080=1");

  script_tag(name:"affected", value:"mgetty on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"g3utils", rpm:"g3utils~1.1.37~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"g3utils-debuginfo", rpm:"g3utils-debuginfo~1.1.37~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mgetty", rpm:"mgetty~1.1.37~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mgetty-debuginfo", rpm:"mgetty-debuginfo~1.1.37~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mgetty-debugsource", rpm:"mgetty-debugsource~1.1.37~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sendfax", rpm:"sendfax~1.1.37~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sendfax-debuginfo", rpm:"sendfax-debuginfo~1.1.37~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
