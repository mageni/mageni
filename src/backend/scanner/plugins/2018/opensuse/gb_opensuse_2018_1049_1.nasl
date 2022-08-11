###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1049_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for PackageKit openSUSE-SU-2018:1049-1 (PackageKit)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851735");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-04-25 08:40:58 +0200 (Wed, 25 Apr 2018)");
  script_cve_id("CVE-2018-1106");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for PackageKit openSUSE-SU-2018:1049-1 (PackageKit)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'PackageKit'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for PackageKit fixes the following security issue:

  - CVE-2018-1106: Drop the polkit rule which could allow users in wheel
  group to install packages without root password (bsc#1086936).

  This update was imported from the SUSE:SLE-12-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-386=1");
  script_tag(name:"affected", value:"PackageKit on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-04/msg00066.html");
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

  if ((res = isrpmvuln(pkg:"PackageKit", rpm:"PackageKit~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"PackageKit-backend-zypp", rpm:"PackageKit-backend-zypp~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"PackageKit-backend-zypp-debuginfo", rpm:"PackageKit-backend-zypp-debuginfo~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"PackageKit-debuginfo", rpm:"PackageKit-debuginfo~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"PackageKit-debugsource", rpm:"PackageKit-debugsource~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"PackageKit-devel", rpm:"PackageKit-devel~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"PackageKit-devel-debuginfo", rpm:"PackageKit-devel-debuginfo~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"PackageKit-gstreamer-plugin", rpm:"PackageKit-gstreamer-plugin~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"PackageKit-gstreamer-plugin-debuginfo", rpm:"PackageKit-gstreamer-plugin-debuginfo~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"PackageKit-gtk3-module", rpm:"PackageKit-gtk3-module~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"PackageKit-gtk3-module-debuginfo", rpm:"PackageKit-gtk3-module-debuginfo~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpackagekit-glib2-18", rpm:"libpackagekit-glib2-18~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpackagekit-glib2-18-debuginfo", rpm:"libpackagekit-glib2-18-debuginfo~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpackagekit-glib2-devel", rpm:"libpackagekit-glib2-devel~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"typelib-1_0-PackageKitGlib-1_0", rpm:"typelib-1_0-PackageKitGlib-1_0~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpackagekit-glib2-18-32bit", rpm:"libpackagekit-glib2-18-32bit~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpackagekit-glib2-18-debuginfo-32bit", rpm:"libpackagekit-glib2-18-debuginfo-32bit~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpackagekit-glib2-devel-32bit", rpm:"libpackagekit-glib2-devel-32bit~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"PackageKit-branding-upstream", rpm:"PackageKit-branding-upstream~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"PackageKit-lang", rpm:"PackageKit-lang~1.1.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
