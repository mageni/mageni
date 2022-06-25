###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_1061_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for calligra openSUSE-SU-2012:1061-1 (calligra)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_tag(name:"affected", value:"calligra on openSUSE 12.2");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Fix buffer overflow in MS Word ODF filter among other
  non-security related bugs.

  Also a version update to 2.4.3 happened:

  * Words:

  - Always show vertical scroll bar to avoid race
  condition (kde#301076)

  - Do not save with an attribute that makes LibreOffice
  and OpenOffice crash (kde#298689 )

  * Kexi:

  - Fixed import from csv when Start at Line value
  changed (kde#302209)

  - Set limit to 255 characters for Text type (VARCHAR)
  (kde#301277 and 301136)
  +    - Remove limits for Text data type, leave as option
  (kde#301277)

  - Fixed data saving when focus policy for one of
  widgets is NoFocus (kde#301109)

  * Krita:

  - Read and set the resolution for psd images

  * Charts:

  - Fix load/save styles of all shapes
  (title, subtitle, axistitles, footer, etc.)

  - Lines in the chart should be displayed (kde#271771)

  - Combined Bar and Line Charts only show bars
  (Trendlines not supported) (kde#288537)

  - Load/save chart type for each dataset (kde#271771 and
  288537)");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2012-08/msg00026.html");
  script_oid("1.3.6.1.4.1.25623.1.0.850417");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-03-11 18:29:18 +0530 (Mon, 11 Mar 2013)");
  script_cve_id("CVE-2012-3456");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("SuSE Update for calligra openSUSE-SU-2012:1061-1 (calligra)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'calligra'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.2");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE12.2")
{

  if ((res = isrpmvuln(pkg:"calligra", rpm:"calligra~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-braindump", rpm:"calligra-braindump~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-braindump-debuginfo", rpm:"calligra-braindump-debuginfo~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-debuginfo", rpm:"calligra-debuginfo~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-debugsource", rpm:"calligra-debugsource~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-devel", rpm:"calligra-devel~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-flow", rpm:"calligra-flow~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-flow-debuginfo", rpm:"calligra-flow-debuginfo~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-karbon", rpm:"calligra-karbon~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-karbon-debuginfo", rpm:"calligra-karbon-debuginfo~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-kexi", rpm:"calligra-kexi~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-kexi-debuginfo", rpm:"calligra-kexi-debuginfo~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-kexi-mssql-driver", rpm:"calligra-kexi-mssql-driver~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-kexi-mssql-driver-debuginfo", rpm:"calligra-kexi-mssql-driver-debuginfo~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-kexi-mysql-driver", rpm:"calligra-kexi-mysql-driver~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-kexi-mysql-driver-debuginfo", rpm:"calligra-kexi-mysql-driver-debuginfo~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-kexi-postgresql-driver", rpm:"calligra-kexi-postgresql-driver~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-kexi-postgresql-driver-debuginfo", rpm:"calligra-kexi-postgresql-driver-debuginfo~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-kexi-spreadsheet-import", rpm:"calligra-kexi-spreadsheet-import~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-kexi-spreadsheet-import-debuginfo", rpm:"calligra-kexi-spreadsheet-import-debuginfo~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-kexi-xbase-driver", rpm:"calligra-kexi-xbase-driver~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-kexi-xbase-driver-debuginfo", rpm:"calligra-kexi-xbase-driver-debuginfo~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-krita", rpm:"calligra-krita~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-krita-debuginfo", rpm:"calligra-krita-debuginfo~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-kthesaurus", rpm:"calligra-kthesaurus~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-kthesaurus-debuginfo", rpm:"calligra-kthesaurus-debuginfo~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-plan", rpm:"calligra-plan~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-plan-debuginfo", rpm:"calligra-plan-debuginfo~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-sheets", rpm:"calligra-sheets~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-sheets-debuginfo", rpm:"calligra-sheets-debuginfo~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-stage", rpm:"calligra-stage~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-stage-debuginfo", rpm:"calligra-stage-debuginfo~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-tools", rpm:"calligra-tools~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-tools-debuginfo", rpm:"calligra-tools-debuginfo~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-words", rpm:"calligra-words~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-words-debuginfo", rpm:"calligra-words-debuginfo~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"calligra-doc", rpm:"calligra-doc~2.4.3~2.4.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
