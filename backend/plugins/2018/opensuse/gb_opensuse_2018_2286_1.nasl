###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2286_1.nasl 13427 2019-02-04 08:52:52Z mmartin $
#
# SuSE Update for libraw openSUSE-SU-2018:2286-1 (libraw)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851848");
  script_version("$Revision: 13427 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-04 09:52:52 +0100 (Mon, 04 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-08-10 06:01:09 +0200 (Fri, 10 Aug 2018)");
  script_cve_id("CVE-2018-5807", "CVE-2018-5810", "CVE-2018-5811", "CVE-2018-5812", "CVE-2018-5813", "CVE-2018-5815");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for libraw openSUSE-SU-2018:2286-1 (libraw)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libraw'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for libraw fixes the following issues:

  The following security vulnerabilities were addressed:

  - CVE-2018-5813: Fixed an error within the 'parse_minolta()' function
  (dcraw/dcraw.c) that could be exploited to trigger an infinite loop via
  a specially crafted file. This could be exploited to cause a
  DoS.(boo#1103200).

  - CVE-2018-5815: Fixed an integer overflow in the
  internal/dcraw_common.cpp:parse_qt() function, that could be exploited
  to cause an infinite loop via a specially crafted Apple QuickTime file.
  (boo#1103206)

  - CVE-2018-5810: Fixed an error within the rollei_load_raw() function
  (internal/dcraw_common.cpp) that could be exploited to cause a
  heap-based buffer overflow and subsequently cause a crash. (boo#1103353)

  - CVE-2018-5811: Fixed an error within the nikon_coolscan_load_raw()
  function (internal/dcraw_common.cpp) that could be exploited to cause an
  out-of-bounds read memory access and subsequently cause a crash.
  (boo#1103359)

  - CVE-2018-5812: Fixed another error within the nikon_coolscan_load_raw()
  function (internal/dcraw_common.cpp) that could be exploited to trigger
  a NULL pointer dereference. (boo#1103360)

  - CVE-2018-5807: Fixed an error within the samsung_load_raw() function
  (internal/dcraw_common.cpp) that could be exploited to cause an
  out-of-bounds read memory access and subsequently cause a crash.
  (boo#1103361)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-849=1");
  script_tag(name:"affected", value:"libraw on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-08/msg00032.html");
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

  if ((res = isrpmvuln(pkg:"libraw-debugsource", rpm:"libraw-debugsource~0.17.1~23.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw-devel", rpm:"libraw-devel~0.17.1~23.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw-devel-static", rpm:"libraw-devel-static~0.17.1~23.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw-tools", rpm:"libraw-tools~0.17.1~23.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw-tools-debuginfo", rpm:"libraw-tools-debuginfo~0.17.1~23.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw15", rpm:"libraw15~0.17.1~23.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw15-debuginfo", rpm:"libraw15-debuginfo~0.17.1~23.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
