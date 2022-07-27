###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3446_1.nasl 12619 2018-12-03 09:51:24Z mmartin $
#
# SuSE Update for zziplib openSUSE-SU-2018:3446-1 (zziplib)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852039");
  script_version("$Revision: 12619 $");
  script_cve_id("CVE-2018-17828");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 10:51:24 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:36:18 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for zziplib openSUSE-SU-2018:3446-1 (zziplib)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-10/msg00066.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zziplib'
  package(s) announced via the openSUSE-SU-2018:3446_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for zziplib fixes the following issues:

  - CVE-2018-17828: Remove any '../' components from pathnames of extracted
  files to avoid path traversal during unpacking. (bsc#1110687)

  This update was imported from the SUSE:SLE-12:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1277=1");

  script_tag(name:"affected", value:"zziplib on openSUSE Leap 42.3.");

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

  if ((res = isrpmvuln(pkg:"libzzip-0-13", rpm:"libzzip-0-13~0.13.67~13.12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libzzip-0-13-debuginfo", rpm:"libzzip-0-13-debuginfo~0.13.67~13.12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zziplib-debugsource", rpm:"zziplib-debugsource~0.13.67~13.12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zziplib-devel", rpm:"zziplib-devel~0.13.67~13.12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zziplib-devel-debuginfo", rpm:"zziplib-devel-debuginfo~0.13.67~13.12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libzzip-0-13-32bit", rpm:"libzzip-0-13-32bit~0.13.67~13.12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libzzip-0-13-debuginfo-32bit", rpm:"libzzip-0-13-debuginfo-32bit~0.13.67~13.12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zziplib-devel-32bit", rpm:"zziplib-devel-32bit~0.13.67~13.12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zziplib-devel-debuginfo-32bit", rpm:"zziplib-devel-debuginfo-32bit~0.13.67~13.12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
