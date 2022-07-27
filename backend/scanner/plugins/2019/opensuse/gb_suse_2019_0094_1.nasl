###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2019_0094_1.nasl 13867 2019-02-26 09:05:01Z asteins $
#
# SuSE Update for libraw openSUSE-SU-2019:0094-1 (libraw)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.852261");
  script_version("$Revision: 13867 $");
  script_cve_id("CVE-2018-20337", "CVE-2018-20363", "CVE-2018-20364", "CVE-2018-20365", "CVE-2018-5817", "CVE-2018-5818", "CVE-2018-5819");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 10:05:01 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-30 04:03:32 +0100 (Wed, 30 Jan 2019)");
  script_name("SuSE Update for libraw openSUSE-SU-2019:0094-1 (libraw)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-01/msg00045.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libraw'
  package(s) announced via the openSUSE-SU-2019:0094_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libraw fixes the following issues:

  Security issues fixed:

  - CVE-2018-20337: Fixed a stack-based buffer overflow in the
  parse_makernote function of dcraw_common.cpp (bsc#1120519)

  - CVE-2018-20365: Fixed a heap-based buffer overflow in the raw2image
  function of libraw_cxx.cpp (bsc#1120500)

  - CVE-2018-20364: Fixed a NULL pointer dereference in the copy_bayer
  function of libraw_cxx.cpp (bsc#1120499)

  - CVE-2018-20363: Fixed a NULL pointer dereference in the raw2image
  function of libraw_cxx.cpp (bsc#1120498)

  - CVE-2018-5817: Fixed an infinite loop in the unpacked_load_raw function
  of dcraw_common.cpp (bsc#1120515)

  - CVE-2018-5818: Fixed an infinite loop in the parse_rollei function of
  dcraw_common.cpp (bsc#1120516)

  - CVE-2018-5819: Fixed a denial of service in the parse_sinar_ia function
  of dcraw_common.cpp (bsc#1120517)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-94=1");

  script_tag(name:"affected", value:"libraw on openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"libraw-debuginfo", rpm:"libraw-debuginfo~0.18.9~lp150.2.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw-debugsource", rpm:"libraw-debugsource~0.18.9~lp150.2.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw-devel", rpm:"libraw-devel~0.18.9~lp150.2.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw-devel-static", rpm:"libraw-devel-static~0.18.9~lp150.2.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw-tools", rpm:"libraw-tools~0.18.9~lp150.2.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw-tools-debuginfo", rpm:"libraw-tools-debuginfo~0.18.9~lp150.2.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw16", rpm:"libraw16~0.18.9~lp150.2.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libraw16-debuginfo", rpm:"libraw16-debuginfo~0.18.9~lp150.2.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
