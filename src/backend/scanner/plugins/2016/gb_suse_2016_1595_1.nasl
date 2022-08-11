###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_1595_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for libxml2 openSUSE-SU-2016:1595-1 (libxml2)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851341");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-17 05:20:19 +0200 (Fri, 17 Jun 2016)");
  script_cve_id("CVE-2015-8806", "CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834",
                "CVE-2016-1835", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839",
                "CVE-2016-1840", "CVE-2016-2073", "CVE-2016-3705", "CVE-2016-4447",
                "CVE-2016-4448", "CVE-2016-4449", "CVE-2016-4483");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for libxml2 openSUSE-SU-2016:1595-1 (libxml2)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for libxml2 fixes the following security issues:

  - CVE-2016-2073, CVE-2015-8806, CVE-2016-1839: A Heap-buffer overread was
  fixed in libxml2/dict.c  [bsc#963963, bsc#965283, bsc#981114].

  - CVE-2016-4483: Code was added to avoid an out of bound access when
  serializing malformed strings [bsc#978395].

  - CVE-2016-1762: Fixed a heap-based buffer overread in xmlNextChar
  [bsc#981040].

  - CVE-2016-1834: Fixed a heap-buffer-overflow in xmlStrncat [bsc#981041].

  - CVE-2016-1833: Fixed a heap-based buffer overread in htmlCurrentChar
  [bsc#981108].

  - CVE-2016-1835: Fixed a heap use-after-free in xmlSAX2AttributeNs
  [bsc#981109].

  - CVE-2016-1837: Fixed a heap use-after-free in htmlParsePubidLiteral and
  htmlParseSystemiteral [bsc#981111].

  - CVE-2016-1838: Fixed a heap-based buffer overread in
  xmlParserPrintFileContextInternal [bsc#981112].

  - CVE-2016-1840: Fixed a heap-buffer-overflow in xmlFAParsePosCharGroup
  [bsc#981115].

  - CVE-2016-4447: Fixed a heap-based buffer-underreads due to xmlParseName
  [bsc#981548].

  - CVE-2016-4448: Fixed some format string warnings with possible format
  string vulnerability [bsc#981549],

  - CVE-2016-4449: Fixed inappropriate fetch of entities content
  [bsc#981550].

  - CVE-2016-3705: Fixed missing increment of recursion counter.

  This update was imported from the SUSE:SLE-12:Update update project.");
  script_tag(name:"affected", value:"libxml2 on openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.9.1~19.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-2-debuginfo", rpm:"libxml2-2-debuginfo~2.9.1~19.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-debugsource", rpm:"libxml2-debugsource~2.9.1~19.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.9.1~19.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.9.1~19.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-tools-debuginfo", rpm:"libxml2-tools-debuginfo~2.9.1~19.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libxml2", rpm:"python-libxml2~2.9.1~19.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libxml2-debuginfo", rpm:"python-libxml2-debuginfo~2.9.1~19.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libxml2-debugsource", rpm:"python-libxml2-debugsource~2.9.1~19.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-2-32bit", rpm:"libxml2-2-32bit~2.9.1~19.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-2-debuginfo-32bit", rpm:"libxml2-2-debuginfo-32bit~2.9.1~19.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-devel-32bit", rpm:"libxml2-devel-32bit~2.9.1~19.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-doc", rpm:"libxml2-doc~2.9.1~19.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
