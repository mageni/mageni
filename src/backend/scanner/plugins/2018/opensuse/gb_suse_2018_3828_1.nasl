###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3828_1.nasl 12832 2018-12-19 07:49:53Z asteins $
#
# SuSE Update for SDL2_image openSUSE-SU-2018:3828-1 (SDL2_image)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852135");
  script_version("$Revision: 12832 $");
  script_cve_id("CVE-2018-3839", "CVE-2018-3977");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-12-19 08:49:53 +0100 (Wed, 19 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-11-21 06:03:41 +0100 (Wed, 21 Nov 2018)");
  script_name("SuSE Update for SDL2_image openSUSE-SU-2018:3828-1 (SDL2_image)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-11/msg00034.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SDL2_image'
  package(s) announced via the openSUSE-SU-2018:3828_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for SDL2_image fixes the following issues:

  Security issues fixed:

  - CVE-2018-3839: Fixed an exploitable code execution vulnerability that
  existed in the XCF image rendering functionality of the Simple
  DirectMedia Layer (bsc#1089087).

  - CVE-2018-3977: Fixed a possible code execution via creafted XCF image
  that could have caused a heap overflow (bsc#1114519).


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1433=1");

  script_tag(name:"affected", value:"SDL2_image on openSUSE Leap 42.3.");

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

  if ((res = isrpmvuln(pkg:"SDL2_image-debugsource", rpm:"SDL2_image-debugsource~2.0.4~13.13.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2_image-2_0-0", rpm:"libSDL2_image-2_0-0~2.0.4~13.13.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2_image-2_0-0-debuginfo", rpm:"libSDL2_image-2_0-0-debuginfo~2.0.4~13.13.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2_image-devel", rpm:"libSDL2_image-devel~2.0.4~13.13.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2_image-2_0-0-32bit", rpm:"libSDL2_image-2_0-0-32bit~2.0.4~13.13.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2_image-2_0-0-debuginfo-32bit", rpm:"libSDL2_image-2_0-0-debuginfo-32bit~2.0.4~13.13.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2_image-devel-32bit", rpm:"libSDL2_image-devel-32bit~2.0.4~13.13.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
