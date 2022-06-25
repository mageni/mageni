###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2313_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for cgit openSUSE-SU-2018:2313-1 (cgit)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851852");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-08-14 05:56:31 +0200 (Tue, 14 Aug 2018)");
  script_cve_id("CVE-2018-14912");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for cgit openSUSE-SU-2018:2313-1 (cgit)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'cgit'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for cgit to version 1.2.1 fixes the following issues:

  The following security vulnerability was addressed:

  - CVE-2018-14912: Fixed a directory traversal vulnerability, when
  enable-http-clone=1 is not turned off (boo#1103799)

  The following other changes were made:

  - Update to upstream release 1.2.1:

  - syntax-highlighting: replace invalid unicode with '?'

  - ui-repolist: properly sort by age

  - ui-patch: fix crash when using path limit

  - Update bundled git to 2.11.1

  - Update to upstream release 1.0:

  * Add repo.homepage/gitweb.homepage setting and homepage tab.

  * Show reverse paths in title bar so that browser tab shows filename.

  * Allow redirects even when caching is turned on.

  * More gracefully deal with unparsable commits.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-864=1");
  script_tag(name:"affected", value:"cgit on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-08/msg00048.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"cgit", rpm:"cgit~1.2.1~13.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cgit-debuginfo", rpm:"cgit-debuginfo~1.2.1~13.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cgit-debugsource", rpm:"cgit-debugsource~1.2.1~13.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
