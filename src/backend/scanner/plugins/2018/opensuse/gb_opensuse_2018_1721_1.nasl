###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1721_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for poppler openSUSE-SU-2018:1721-1 (poppler)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851791");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-06-17 05:53:19 +0200 (Sun, 17 Jun 2018)");
  script_cve_id("CVE-2017-1000456", "CVE-2017-14517", "CVE-2017-14518", "CVE-2017-14520",
                "CVE-2017-14617", "CVE-2017-14928", "CVE-2017-14975", "CVE-2017-14976",
                "CVE-2017-14977", "CVE-2017-15565", "CVE-2017-9865");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for poppler openSUSE-SU-2018:1721-1 (poppler)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"This update for poppler fixes the following issues:

  These security issues were fixed:

  - CVE-2017-14517: Prevent NULL Pointer dereference in the
  XRef::parseEntry() function via a crafted PDF document (bsc#1059066).

  - CVE-2017-9865: Fixed a stack-based buffer overflow vulnerability in
  GfxState.cc that would have allowed attackers to facilitate a
  denial-of-service attack via specially crafted PDF documents.
  (bsc#1045939)

  - CVE-2017-14518: Remedy a floating point exception in
  isImageInterpolationRequired() that could have been exploited using a
  specially crafted PDF document. (bsc#1059101)

  - CVE-2017-14520: Remedy a floating point exception in
  Splash::scaleImageYuXd() that could have been exploited using a
  specially crafted PDF document. (bsc#1059155)

  - CVE-2017-14617: Fixed a floating point exception in Stream.cc, which may
  lead to a potential attack when handling malicious PDF files.
  (bsc#1060220)

  - CVE-2017-14928: Fixed a NULL Pointer dereference in
  AnnotRichMedia::Configuration::Configuration() in Annot.cc, which may
  lead to a potential attack when handling malicious PDF files.
  (bsc#1061092)

  - CVE-2017-14975: Fixed a NULL pointer dereference vulnerability, that
  existed because a data structure in FoFiType1C.cc was not initialized,
  which allowed an attacker to launch a denial of service attack.
  (bsc#1061263)

  - CVE-2017-14976: Fixed a heap-based buffer over-read vulnerability in
  FoFiType1C.cc that occurred when an out-of-bounds font dictionary index
  was encountered, which allowed an attacker to launch a denial of service
  attack. (bsc#1061264)

  - CVE-2017-14977: Fixed a NULL pointer dereference vulnerability in the
  FoFiTrueType::getCFFBlock() function in FoFiTrueType.cc that occurred
  due to lack of validation of a table pointer, which allows an attacker
  to launch a denial of service attack. (bsc#1061265)

  - CVE-2017-15565: Prevent NULL Pointer dereference in the
  GfxImageColorMap::getGrayLine() function via a crafted PDF document
  (bsc#1064593).

  - CVE-2017-1000456: Validate boundaries in TextPool::addWord to prevent
  overflows in subsequent calculations (bsc#1074453).

  This update was imported from the SUSE:SLE-12-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-648=1");
  script_tag(name:"affected", value:"poppler on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-06/msg00032.html");
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

  if ((res = isrpmvuln(pkg:"libpoppler-cpp0", rpm:"libpoppler-cpp0~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-cpp0-debuginfo", rpm:"libpoppler-cpp0-debuginfo~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-devel", rpm:"libpoppler-devel~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-glib-devel", rpm:"libpoppler-glib-devel~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-glib8", rpm:"libpoppler-glib8~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-glib8-debuginfo", rpm:"libpoppler-glib8-debuginfo~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt4-4", rpm:"libpoppler-qt4-4~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt4-4-debuginfo", rpm:"libpoppler-qt4-4-debuginfo~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt4-devel", rpm:"libpoppler-qt4-devel~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt5-1", rpm:"libpoppler-qt5-1~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt5-1-debuginfo", rpm:"libpoppler-qt5-1-debuginfo~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt5-devel", rpm:"libpoppler-qt5-devel~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler60", rpm:"libpoppler60~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler60-debuginfo", rpm:"libpoppler60-debuginfo~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"poppler-debugsource", rpm:"poppler-debugsource~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"poppler-qt-debugsource", rpm:"poppler-qt-debugsource~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"poppler-qt5-debugsource", rpm:"poppler-qt5-debugsource~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"poppler-tools", rpm:"poppler-tools~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"poppler-tools-debuginfo", rpm:"poppler-tools-debuginfo~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"typelib-1_0-Poppler-0_18", rpm:"typelib-1_0-Poppler-0_18~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-cpp0-32bit", rpm:"libpoppler-cpp0-32bit~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-cpp0-debuginfo-32bit", rpm:"libpoppler-cpp0-debuginfo-32bit~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-glib8-32bit", rpm:"libpoppler-glib8-32bit~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-glib8-debuginfo-32bit", rpm:"libpoppler-glib8-debuginfo-32bit~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt4-4-32bit", rpm:"libpoppler-qt4-4-32bit~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt4-4-debuginfo-32bit", rpm:"libpoppler-qt4-4-debuginfo-32bit~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt5-1-32bit", rpm:"libpoppler-qt5-1-32bit~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt5-1-debuginfo-32bit", rpm:"libpoppler-qt5-1-debuginfo-32bit~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler60-32bit", rpm:"libpoppler60-32bit~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler60-debuginfo-32bit", rpm:"libpoppler60-debuginfo-32bit~0.43.0~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
