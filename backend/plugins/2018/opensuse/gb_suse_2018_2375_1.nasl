###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2375_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for python-Django1 openSUSE-SU-2018:2375-1 (python-Django1)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852035");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2018-14574");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:36:06 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for python-Django1 openSUSE-SU-2018:2375-1 (python-Django1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-08/msg00054.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-Django1'
  package(s) announced via the openSUSE-SU-2018:2375_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-Django1 to version 1.11.15 fixes the following
  issues:

  The following security vulnerability was fixed:

  - CVE-2018-14574: Fixed an open redirect possibility in CommonMiddleware
  (boo#1102680)

  The following other bugs were fixed:

  - Fixed WKBWriter.write() and write_hex() for empty polygons on GEOS 3.6.1+

  - Fixed a regression where altering a field with a unique constraint may
  drop and rebuild more foreign keys than necessary

  - Fixed crashes in django.contrib.admindocs when a view is a callable
  object, such as django.contrib.syndication.views.Feed

  - Fixed a regression where QuerySet.values() or values_list() after
  combining an annotated and unannotated queryset with union(),
  difference(), or intersection() crashed due to mismatching columns


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-875=1");

  script_tag(name:"affected", value:"python-Django1 on openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"python2-Django1", rpm:"python2-Django1~1.11.15~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
