###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1116_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for LibreOffice SUSE-SU-2014:1116-1 (LibreOffice)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851049");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 18:56:26 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2013-4156", "CVE-2014-3575");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for LibreOffice SUSE-SU-2014:1116-1 (LibreOffice)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'LibreOffice'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"LibreOffice was updated to version 4.0.3.3.26. (SUSE 4.0-patch26, tag
  suse-4.0-26, based on upstream 4.0.3.3).

  Two security issues have been fixed:

  * DOCM memory corruption vulnerability. (CVE-2013-4156, bnc#831578)

  * Data exposure using crafted OLE objects. (CVE-2014-3575, bnc#893141)

  The following non-security issues have been fixed:

  * chart shown flipped (bnc#834722)

  * chart missing dataset (bnc#839727)

  * import new line in text (bnc#828390)

  * lines running off screens (bnc#819614)

  * add set-all language menu (bnc#863021)

  * text rotation (bnc#783433, bnc#862510)

  * page border shadow testcase (bnc#817956)

  * one more clickable field fix (bnc#802888)

  * multilevel labels are rotated (bnc#820273)

  * incorrect nested table margins (bnc#816593)

  * use BitmapURL only if its valid (bnc#821567)

  * import gradfill for text colors (bnc#870234)

  * fix undo of paragraph attributes (bnc#828598)

  * stop-gap solution to avoid crash (bnc#830205)

  * import images with duotone filter (bnc#820077)

  * missing drop downs for autofilter (bnc#834705)

  * typos in first page style creation (bnc#820836)

  * labels wrongly interpreted as dates (bnc#834720)

  * RTF import of fFilled shape property (bnc#825305)

  * placeholders text size is not correct (bnc#831457)

  * cells value formatted with wrong output (bnc#821795)

  * RTF import of freeform shape coordinates (bnc#823655)

  * styles (rename &amp ) copy to different decks (bnc#757432)

  * XLSX Chart import with internal data table (bnc#819822)

  * handle M.d.yyyy date format in DOCX import (bnc#820509)

  * paragraph style in empty first page header (bnc#823651)

  * copying slides having same master page name (bnc#753460)

  * printing handouts using the default, 'Order' (bnc#835985)

  * wrap polygon was based on dest size of picture (bnc#820800)

  * added common flags support for SEQ field import (bnc#825976)

  * hyperlinks of illustration index in DOCX export (bnc#834035)

  * allow insertion of redlines with an empty author (bnc#837302)

  * handle drawinglayer rectangle inset in VML import (bnc#779642)

  * don't apply complex font size to non-complex font (bnc#820819)

  * issue with negative seeks in win32 shell extension (bnc#829017)

  * slide appears quite garbled when imported from PPTX (bnc#593612)

  * initial MCE support in writerfilter ooxml tokenizer (bnc#820503)

  * MSWord uses \xb for linebreaks in DB fields, take 2 (bnc#878854)

  * try harder to convert floating tables to text frames (bnc#779620)

  * itemstate in parent style incorrectly reported as set (bnc#819865)

  * default color h ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"LibreOffice on SUSE Linux Enterprise Desktop 11 SP3");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLED11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLED11.0SP3")
{

  if ((res = isrpmvuln(pkg:"libreoffice", rpm:"libreoffice~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-base", rpm:"libreoffice-base~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-base-drivers-postgresql", rpm:"libreoffice-base-drivers-postgresql~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-base-extensions", rpm:"libreoffice-base-extensions~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-calc", rpm:"libreoffice-calc~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-calc-extensions", rpm:"libreoffice-calc-extensions~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-draw", rpm:"libreoffice-draw~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-draw-extensions", rpm:"libreoffice-draw-extensions~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-filters-optional", rpm:"libreoffice-filters-optional~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-gnome", rpm:"libreoffice-gnome~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-impress", rpm:"libreoffice-impress~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-impress-extensions", rpm:"libreoffice-impress-extensions~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-kde", rpm:"libreoffice-kde~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-kde4", rpm:"libreoffice-kde4~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-mailmerge", rpm:"libreoffice-mailmerge~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-math", rpm:"libreoffice-math~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-mono", rpm:"libreoffice-mono~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-officebean", rpm:"libreoffice-officebean~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-pyuno", rpm:"libreoffice-pyuno~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-writer", rpm:"libreoffice-writer~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-writer-extensions", rpm:"libreoffice-writer-extensions~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-cs", rpm:"libreoffice-help-cs~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-da", rpm:"libreoffice-help-da~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-de", rpm:"libreoffice-help-de~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-en-GB", rpm:"libreoffice-help-en-GB~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-en-US", rpm:"libreoffice-help-en-US~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-es", rpm:"libreoffice-help-es~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-fr", rpm:"libreoffice-help-fr~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-gu-IN", rpm:"libreoffice-help-gu-IN~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-hi-IN", rpm:"libreoffice-help-hi-IN~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-hu", rpm:"libreoffice-help-hu~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-it", rpm:"libreoffice-help-it~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-ja", rpm:"libreoffice-help-ja~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-ko", rpm:"libreoffice-help-ko~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-nl", rpm:"libreoffice-help-nl~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-pl", rpm:"libreoffice-help-pl~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-pt", rpm:"libreoffice-help-pt~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-pt-BR", rpm:"libreoffice-help-pt-BR~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-ru", rpm:"libreoffice-help-ru~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-sv", rpm:"libreoffice-help-sv~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-zh-CN", rpm:"libreoffice-help-zh-CN~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-help-zh-TW", rpm:"libreoffice-help-zh-TW~4.0.3.3.26~0.6.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-icon-themes", rpm:"libreoffice-icon-themes~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-af", rpm:"libreoffice-l10n-af~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-ar", rpm:"libreoffice-l10n-ar~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-ca", rpm:"libreoffice-l10n-ca~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-cs", rpm:"libreoffice-l10n-cs~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-da", rpm:"libreoffice-l10n-da~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-de", rpm:"libreoffice-l10n-de~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-en-GB", rpm:"libreoffice-l10n-en-GB~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-es", rpm:"libreoffice-l10n-es~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-fi", rpm:"libreoffice-l10n-fi~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-fr", rpm:"libreoffice-l10n-fr~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-gu-IN", rpm:"libreoffice-l10n-gu-IN~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-hi-IN", rpm:"libreoffice-l10n-hi-IN~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-hu", rpm:"libreoffice-l10n-hu~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-it", rpm:"libreoffice-l10n-it~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-ja", rpm:"libreoffice-l10n-ja~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-ko", rpm:"libreoffice-l10n-ko~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-nb", rpm:"libreoffice-l10n-nb~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-nl", rpm:"libreoffice-l10n-nl~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-nn", rpm:"libreoffice-l10n-nn~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-pl", rpm:"libreoffice-l10n-pl~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-pt", rpm:"libreoffice-l10n-pt~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-pt-BR", rpm:"libreoffice-l10n-pt-BR~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-ru", rpm:"libreoffice-l10n-ru~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-sk", rpm:"libreoffice-l10n-sk~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-sv", rpm:"libreoffice-l10n-sv~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-xh", rpm:"libreoffice-l10n-xh~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-zh-CN", rpm:"libreoffice-l10n-zh-CN~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-zh-TW", rpm:"libreoffice-l10n-zh-TW~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreoffice-l10n-zu", rpm:"libreoffice-l10n-zu~4.0.3.3.26~0.6.2", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
