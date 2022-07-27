###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2376_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for libheimdal openSUSE-SU-2018:2376-1 (libheimdal)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851856");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-08-17 05:57:36 +0200 (Fri, 17 Aug 2018)");
  script_cve_id("CVE-2017-17439");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for libheimdal openSUSE-SU-2018:2376-1 (libheimdal)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libheimdal'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for libheimdal to version 7.5.0 fixes the following issues:

  The following security vulnerability was fixed:

  - CVE-2017-17439: Fixed a remote denial of service vulnerability through
  which remote unauthenticated attackers were able to crash the KDC by
  sending a crafted UDP packet containing empty data fields for client
  name or realm (boo#1071675)

  The following other bugs were fixed:

  - Override the build date (boo#1047218)

  - Use constant hostname (boo#1084909)

  - Handle long input lines when reloading database dumps

  - In pre-forked mode, correctly clear the process ids of exited children,
  allowing new child processes to replace the old.

  - Fixed incorrect KDC response when no-cross realm TGT exists, allowing
  client requests to fail quickly rather than time out after trying to get
  a correct answer from each KDC.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-876=1");
  script_tag(name:"affected", value:"libheimdal on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-08/msg00055.html");
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

  if ((res = isrpmvuln(pkg:"libheimdal", rpm:"libheimdal~7.5.0~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libheimdal-debuginfo", rpm:"libheimdal-debuginfo~7.5.0~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libheimdal-debugsource", rpm:"libheimdal-debugsource~7.5.0~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libheimdal-devel", rpm:"libheimdal-devel~7.5.0~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
