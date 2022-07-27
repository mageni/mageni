###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2819_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for liblouis openSUSE-SU-2018:2819-1 (liblouis)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851903");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-25 08:19:53 +0200 (Tue, 25 Sep 2018)");
  script_cve_id("CVE-2018-11440", "CVE-2018-11577", "CVE-2018-11683", "CVE-2018-11684", "CVE-2018-11685", "CVE-2018-12085");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for liblouis openSUSE-SU-2018:2819-1 (liblouis)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'liblouis'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for liblouis fixes the following issues:

  Security issues fixed:

  - CVE-2018-11440: Fixed a stack-based buffer overflow in the function
  parseChars() in compileTranslationTable.c (bsc#1095189)

  - CVE-2018-11577: Fixed a segmentation fault in lou_logPrint in logging.c
  (bsc#1095945)

  - CVE-2018-11683: Fixed a stack-based buffer overflow in the function
  parseChars() in compileTranslationTable.c (different vulnerability than
  CVE-2018-11440) (bsc#1095827)

  - CVE-2018-11684: Fixed stack-based buffer overflow in the function
  includeFile() in compileTranslationTable.c (bsc#1095826)

  - CVE-2018-11685: Fixed a stack-based buffer overflow in the function
  compileHyphenation() in compileTranslationTable.c (bsc#1095825)

  - CVE-2018-12085: Fixed a stack-based buffer overflow in the function
  parseChars() in compileTranslationTable.c (different vulnerability than
  CVE-2018-11440) (bsc#1097103)

  This update was imported from the SUSE:SLE-12-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1039=1");
  script_tag(name:"affected", value:"liblouis on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-09/msg00067.html");
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

  if ((res = isrpmvuln(pkg:"liblouis-data", rpm:"liblouis-data~2.6.4~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblouis-debugsource", rpm:"liblouis-debugsource~2.6.4~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblouis-devel", rpm:"liblouis-devel~2.6.4~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblouis-doc", rpm:"liblouis-doc~2.6.4~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblouis-tools", rpm:"liblouis-tools~2.6.4~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblouis-tools-debuginfo", rpm:"liblouis-tools-debuginfo~2.6.4~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblouis9", rpm:"liblouis9~2.6.4~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblouis9-debuginfo", rpm:"liblouis9-debuginfo~2.6.4~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-louis", rpm:"python-louis~2.6.4~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
