###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2132_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for mercurial openSUSE-SU-2018:2132-1 (mercurial)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852072");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2018-13346", "CVE-2018-13347", "CVE-2018-13348");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:41:37 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for mercurial openSUSE-SU-2018:2132-1 (mercurial)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-07/msg00049.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mercurial'
  package(s) announced via the openSUSE-SU-2018:2132_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mercurial fixes the following issues:

  Security issues fixed:

  - CVE-2018-13346: Fix mpatch_apply function in mpatch.c that incorrectly
  proceeds in cases where the fragment start is past the end of the
  original data (bsc#1100354).

  - CVE-2018-13347: Fix mpatch.c that mishandles integer addition and
  subtraction (bsc#1100355).

  - CVE-2018-13348: Fix the mpatch_decode function in mpatch.c that
  mishandles certain situations where there should be at least 12 bytes
  remaining after thecurrent position in the patch data (bsc#1100353).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-772=1");

  script_tag(name:"affected", value:"mercurial on openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"mercurial", rpm:"mercurial~4.5.2~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mercurial-debuginfo", rpm:"mercurial-debuginfo~4.5.2~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mercurial-debugsource", rpm:"mercurial-debugsource~4.5.2~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mercurial-lang", rpm:"mercurial-lang~4.5.2~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
