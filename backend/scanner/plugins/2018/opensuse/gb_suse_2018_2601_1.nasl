###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2601_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for spice-gtk openSUSE-SU-2018:2601-1 (spice-gtk)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851878");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-05 06:54:06 +0200 (Wed, 05 Sep 2018)");
  script_cve_id("CVE-2018-10873", "CVE-2018-10893");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for spice-gtk openSUSE-SU-2018:2601-1 (spice-gtk)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'spice-gtk'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for spice-gtk fixes the following issues:

  Security issues fixed:

  - CVE-2018-10873: Fix potential heap corruption when demarshalling
  (bsc#1104448)

  - CVE-2018-10893: Avoid buffer overflow on image lz checks (bsc#1101295)

  This update was imported from the SUSE:SLE-12-SP3:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-958=1");
  script_tag(name:"affected", value:"spice-gtk on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-09/msg00008.html");
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

  if ((res = isrpmvuln(pkg:"spice-gtk-lang", rpm:"spice-gtk-lang~0.33~2.7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libspice-client-glib-2_0-8", rpm:"libspice-client-glib-2_0-8~0.33~2.7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libspice-client-glib-2_0-8-debuginfo", rpm:"libspice-client-glib-2_0-8-debuginfo~0.33~2.7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libspice-client-glib-helper", rpm:"libspice-client-glib-helper~0.33~2.7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libspice-client-glib-helper-debuginfo", rpm:"libspice-client-glib-helper-debuginfo~0.33~2.7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libspice-client-gtk-3_0-5", rpm:"libspice-client-gtk-3_0-5~0.33~2.7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libspice-client-gtk-3_0-5-debuginfo", rpm:"libspice-client-gtk-3_0-5-debuginfo~0.33~2.7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libspice-controller0", rpm:"libspice-controller0~0.33~2.7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libspice-controller0-debuginfo", rpm:"libspice-controller0-debuginfo~0.33~2.7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-gtk", rpm:"spice-gtk~0.33~2.7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-gtk-debuginfo", rpm:"spice-gtk-debuginfo~0.33~2.7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-gtk-debugsource", rpm:"spice-gtk-debugsource~0.33~2.7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-gtk-devel", rpm:"spice-gtk-devel~0.33~2.7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"typelib-1_0-SpiceClientGlib-2_0", rpm:"typelib-1_0-SpiceClientGlib-2_0~0.33~2.7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"typelib-1_0-SpiceClientGtk-3_0", rpm:"typelib-1_0-SpiceClientGtk-3_0~0.33~2.7.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
