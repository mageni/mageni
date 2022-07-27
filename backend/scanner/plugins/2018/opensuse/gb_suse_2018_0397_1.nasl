###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0397_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for plasma5-workspace openSUSE-SU-2018:0397-1 (plasma5-workspace)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851697");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-02-10 07:53:58 +0100 (Sat, 10 Feb 2018)");
  script_cve_id("CVE-2018-6790", "CVE-2018-6791");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for plasma5-workspace openSUSE-SU-2018:0397-1 (plasma5-workspace)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'plasma5-workspace'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for plasma5-workspace fixes security issues and bugs.

  The following vulnerabilities were fixed:

  - CVE-2018-6790: Desktop notifications could have been used to load
  arbitrary remote images into Plasma, allowing for client IP discovery
  (boo#1079429)

  - CVE-2018-6791: A specially crafted file system label may have allowed
  execution of arbitrary code (boo#1079751)

  The following bugs were fixed:

  - Plasma could freeze with certain notifications (boo#1013550)");
  script_tag(name:"affected", value:"plasma5-workspace on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-02/msg00010.html");
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

  if ((res = isrpmvuln(pkg:"drkonqi5", rpm:"drkonqi5~5.8.7~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drkonqi5-debuginfo", rpm:"drkonqi5-debuginfo~5.8.7~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"plasma5-workspace", rpm:"plasma5-workspace~5.8.7~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"plasma5-workspace-debuginfo", rpm:"plasma5-workspace-debuginfo~5.8.7~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"plasma5-workspace-debugsource", rpm:"plasma5-workspace-debugsource~5.8.7~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"plasma5-workspace-devel", rpm:"plasma5-workspace-devel~5.8.7~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"plasma5-workspace-libs", rpm:"plasma5-workspace-libs~5.8.7~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"plasma5-workspace-libs-debuginfo", rpm:"plasma5-workspace-libs-debuginfo~5.8.7~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"plasma5-workspace-lang", rpm:"plasma5-workspace-lang~5.8.7~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
