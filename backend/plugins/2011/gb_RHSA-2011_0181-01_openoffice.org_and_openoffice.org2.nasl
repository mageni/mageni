###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for openoffice.org and openoffice.org2 RHSA-2011:0181-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-January/msg00024.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870386");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-01-31 15:15:14 +0100 (Mon, 31 Jan 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-3450", "CVE-2010-3451", "CVE-2010-3452", "CVE-2010-3453", "CVE-2010-3454", "CVE-2010-4643");
  script_name("RedHat Update for openoffice.org and openoffice.org2 RHSA-2011:0181-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openoffice.org and openoffice.org2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_4");
  script_tag(name:"affected", value:"openoffice.org and openoffice.org2 on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"OpenOffice.org is an office productivity suite that includes desktop
  applications, such as a word processor, spreadsheet application,
  presentation manager, formula editor, and a drawing program.

  An array index error and an integer signedness error were found in the way
  OpenOffice.org parsed certain Rich Text Format (RTF) files. An attacker
  could use these flaws to create a specially-crafted RTF file that, when
  opened, would cause OpenOffice.org to crash or, possibly, execute arbitrary
  code with the privileges of the user running OpenOffice.org.
  (CVE-2010-3451, CVE-2010-3452)

  A heap-based buffer overflow flaw and an array index error were found in
  the way OpenOffice.org parsed certain Microsoft Office Word documents. An
  attacker could use these flaws to create a specially-crafted Microsoft
  Office Word document that, when opened, would cause OpenOffice.org to crash
  or, possibly, execute arbitrary code with the privileges of the user
  running OpenOffice.org. (CVE-2010-3453, CVE-2010-3454)

  A heap-based buffer overflow flaw was found in the way OpenOffice.org
  parsed certain TARGA (Truevision TGA) files. An attacker could use this
  flaw to create a specially-crafted TARGA file. If a document containing
  this specially-crafted TARGA file was opened, or if a user tried to insert
  the file into an existing document, it would cause OpenOffice.org to crash
  or, possibly, execute arbitrary code with the privileges of the user
  running OpenOffice.org. (CVE-2010-4643)

  A directory traversal flaw was found in the way OpenOffice.org handled
  the installation of XSLT filter descriptions packaged in Java Archive (JAR)
  files, as well as the installation of OpenOffice.org Extension (.oxt)
  files. An attacker could use these flaws to create a specially-crafted XSLT
  filter description or extension file that, when opened, would cause the
  OpenOffice.org Extension Manager to modify files accessible to the user
  installing the JAR or extension file. (CVE-2010-3450)

  Red Hat would like to thank OpenOffice.org for reporting the CVE-2010-3451,
  CVE-2010-3452, CVE-2010-3453, CVE-2010-3454, and CVE-2010-4643 issues.
  Upstream acknowledges Dan Rosenberg of Virtual Security Research as the
  original reporter of the CVE-2010-3451, CVE-2010-3452, CVE-2010-3453, and
  CVE-2010-3454 issues.

  All OpenOffice.org users are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues. All running
  instances of OpenOffice.org applications must be restarted for this update
  to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"openoffice.org", rpm:"openoffice.org~1.1.5~10.7.el4_8.10", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-debuginfo", rpm:"openoffice.org-debuginfo~1.1.5~10.7.el4_8.10", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-i18n", rpm:"openoffice.org-i18n~1.1.5~10.7.el4_8.10", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-kde", rpm:"openoffice.org-kde~1.1.5~10.7.el4_8.10", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-libs", rpm:"openoffice.org-libs~1.1.5~10.7.el4_8.10", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-base", rpm:"openoffice.org2-base~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-calc", rpm:"openoffice.org2-calc~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-core", rpm:"openoffice.org2-core~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-debuginfo", rpm:"openoffice.org2-debuginfo~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-draw", rpm:"openoffice.org2-draw~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-emailmerge", rpm:"openoffice.org2-emailmerge~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-graphicfilter", rpm:"openoffice.org2-graphicfilter~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-impress", rpm:"openoffice.org2-impress~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-javafilter", rpm:"openoffice.org2-javafilter~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-af_ZA", rpm:"openoffice.org2-langpack-af_ZA~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-ar", rpm:"openoffice.org2-langpack-ar~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-bg_BG", rpm:"openoffice.org2-langpack-bg_BG~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-bn", rpm:"openoffice.org2-langpack-bn~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-ca_ES", rpm:"openoffice.org2-langpack-ca_ES~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-cs_CZ", rpm:"openoffice.org2-langpack-cs_CZ~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-cy_GB", rpm:"openoffice.org2-langpack-cy_GB~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-da_DK", rpm:"openoffice.org2-langpack-da_DK~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-de", rpm:"openoffice.org2-langpack-de~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-el_GR", rpm:"openoffice.org2-langpack-el_GR~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-es", rpm:"openoffice.org2-langpack-es~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-et_EE", rpm:"openoffice.org2-langpack-et_EE~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-eu_ES", rpm:"openoffice.org2-langpack-eu_ES~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-fi_FI", rpm:"openoffice.org2-langpack-fi_FI~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-fr", rpm:"openoffice.org2-langpack-fr~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-ga_IE", rpm:"openoffice.org2-langpack-ga_IE~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-gl_ES", rpm:"openoffice.org2-langpack-gl_ES~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-gu_IN", rpm:"openoffice.org2-langpack-gu_IN~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-he_IL", rpm:"openoffice.org2-langpack-he_IL~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-hi_IN", rpm:"openoffice.org2-langpack-hi_IN~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-hr_HR", rpm:"openoffice.org2-langpack-hr_HR~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-hu_HU", rpm:"openoffice.org2-langpack-hu_HU~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-it", rpm:"openoffice.org2-langpack-it~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-ja_JP", rpm:"openoffice.org2-langpack-ja_JP~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-ko_KR", rpm:"openoffice.org2-langpack-ko_KR~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-lt_LT", rpm:"openoffice.org2-langpack-lt_LT~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-ms_MY", rpm:"openoffice.org2-langpack-ms_MY~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-nb_NO", rpm:"openoffice.org2-langpack-nb_NO~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-nl", rpm:"openoffice.org2-langpack-nl~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-nn_NO", rpm:"openoffice.org2-langpack-nn_NO~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-pa_IN", rpm:"openoffice.org2-langpack-pa_IN~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-pl_PL", rpm:"openoffice.org2-langpack-pl_PL~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-pt_BR", rpm:"openoffice.org2-langpack-pt_BR~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-pt_PT", rpm:"openoffice.org2-langpack-pt_PT~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-ru", rpm:"openoffice.org2-langpack-ru~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-sk_SK", rpm:"openoffice.org2-langpack-sk_SK~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-sl_SI", rpm:"openoffice.org2-langpack-sl_SI~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-sr_CS", rpm:"openoffice.org2-langpack-sr_CS~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-sv", rpm:"openoffice.org2-langpack-sv~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-ta_IN", rpm:"openoffice.org2-langpack-ta_IN~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-th_TH", rpm:"openoffice.org2-langpack-th_TH~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-tr_TR", rpm:"openoffice.org2-langpack-tr_TR~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-zh_CN", rpm:"openoffice.org2-langpack-zh_CN~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-zh_TW", rpm:"openoffice.org2-langpack-zh_TW~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-langpack-zu_ZA", rpm:"openoffice.org2-langpack-zu_ZA~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-math", rpm:"openoffice.org2-math~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-pyuno", rpm:"openoffice.org2-pyuno~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-testtools", rpm:"openoffice.org2-testtools~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-writer", rpm:"openoffice.org2-writer~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org2-xsltfilter", rpm:"openoffice.org2-xsltfilter~2.0.4~5.7.0.6.1.el4_8.8", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
