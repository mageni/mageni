###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2827_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for jhead openSUSE-SU-2018:2827-1 (jhead)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851909");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-25 08:24:10 +0200 (Tue, 25 Sep 2018)");
  script_cve_id("CVE-2016-3822", "CVE-2018-16554");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for jhead openSUSE-SU-2018:2827-1 (jhead)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'jhead'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for jhead fixes the following security issues:

  - CVE-2016-3822: jhead remote attackers to execute arbitrary code or cause
  a denial of service (out-of-bounds access) via crafted EXIF data
  (bsc#1108480).

  - CVE-2018-16554: The ProcessGpsInfo function may have allowed a remote
  attacker to cause a denial-of-service attack or unspecified other impact
  via a malicious JPEG file, because of inconsistency between float and
  double in a sprintf format string during TAG_GPS_ALT handling
  (bsc#1108480).


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1044=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1044=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1044=1");
  script_tag(name:"affected", value:"jhead on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-09/msg00069.html");
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

  if ((res = isrpmvuln(pkg:"jhead", rpm:"jhead~3.00~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jhead-debuginfo", rpm:"jhead-debuginfo~3.00~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jhead-debugsource", rpm:"jhead-debugsource~3.00~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
