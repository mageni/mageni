###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for openoffice.org FEDORA-2007-4120
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "OpenOffice.org is an Open Source, community-developed, multi-platform
  office productivity suite.  It includes the key desktop applications,
  such as a word processor, spreadsheet, presentation manager, formula
  editor and drawing program, with a user interface and feature set
  similar to other office suites.  Sophisticated and flexible,
  OpenOffice.org also works transparently with a variety of file
  formats, including Microsoft Office.

  Usage: Simply type &quot;ooffice&quot; to run OpenOffice.org or select the
  requested component (Writer, Calc, Impress, etc.) from your
  desktop menu. On first start a few files will be installed in the
  user's home, if necessary.";

tag_affected = "openoffice.org on Fedora 7";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-December/msg00134.html");
  script_oid("1.3.6.1.4.1.25623.1.0.307229");
  script_version("$Revision: 6623 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:10:20 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:27:46 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2007-4120");
  script_cve_id("CVE-2007-4575", "CVE-2007-2834", "CVE-2007-0245");
  script_name( "Fedora Update for openoffice.org FEDORA-2007-4120");

  script_tag(name:"summary", value:"Check for the Version of openoffice.org");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC7")
{

  if ((res = isrpmvuln(pkg:"openoffice.org", rpm:"openoffice.org~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-debuginfo", rpm:"openoffice.org-debuginfo~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-impress", rpm:"openoffice.org-impress~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-el_GR", rpm:"openoffice.org-langpack-el_GR~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-headless", rpm:"openoffice.org-headless~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-graphicfilter", rpm:"openoffice.org-graphicfilter~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-testtools", rpm:"openoffice.org-testtools~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-sl_SI", rpm:"openoffice.org-langpack-sl_SI~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nn_NO", rpm:"openoffice.org-langpack-nn_NO~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ja_JP", rpm:"openoffice.org-langpack-ja_JP~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-sr_CS", rpm:"openoffice.org-langpack-sr_CS~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-xh_ZA", rpm:"openoffice.org-langpack-xh_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-bn", rpm:"openoffice.org-langpack-bn~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-pt_PT", rpm:"openoffice.org-langpack-pt_PT~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-gu_IN", rpm:"openoffice.org-langpack-gu_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-core", rpm:"openoffice.org-core~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ar", rpm:"openoffice.org-langpack-ar~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-th_TH", rpm:"openoffice.org-langpack-th_TH~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-draw", rpm:"openoffice.org-draw~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ko_KR", rpm:"openoffice.org-langpack-ko_KR~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-pt_BR", rpm:"openoffice.org-langpack-pt_BR~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-xsltfilter", rpm:"openoffice.org-xsltfilter~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ca_ES", rpm:"openoffice.org-langpack-ca_ES~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-tn_ZA", rpm:"openoffice.org-langpack-tn_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-emailmerge", rpm:"openoffice.org-emailmerge~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-fr", rpm:"openoffice.org-langpack-fr~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ml_IN", rpm:"openoffice.org-langpack-ml_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-hu_HU", rpm:"openoffice.org-langpack-hu_HU~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ur", rpm:"openoffice.org-langpack-ur~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nb_NO", rpm:"openoffice.org-langpack-nb_NO~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-javafilter", rpm:"openoffice.org-javafilter~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-st_ZA", rpm:"openoffice.org-langpack-st_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ru", rpm:"openoffice.org-langpack-ru~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-it", rpm:"openoffice.org-langpack-it~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-sv", rpm:"openoffice.org-langpack-sv~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-hr_HR", rpm:"openoffice.org-langpack-hr_HR~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-writer", rpm:"openoffice.org-writer~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ve_ZA", rpm:"openoffice.org-langpack-ve_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-pyuno", rpm:"openoffice.org-pyuno~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-af_ZA", rpm:"openoffice.org-langpack-af_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ts_ZA", rpm:"openoffice.org-langpack-ts_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-bg_BG", rpm:"openoffice.org-langpack-bg_BG~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-math", rpm:"openoffice.org-math~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-gl_ES", rpm:"openoffice.org-langpack-gl_ES~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-lt_LT", rpm:"openoffice.org-langpack-lt_LT~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-sdk", rpm:"openoffice.org-sdk~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-da_DK", rpm:"openoffice.org-langpack-da_DK~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-calc", rpm:"openoffice.org-calc~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-fi_FI", rpm:"openoffice.org-langpack-fi_FI~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ga_IE", rpm:"openoffice.org-langpack-ga_IE~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-tr_TR", rpm:"openoffice.org-langpack-tr_TR~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-pl_PL", rpm:"openoffice.org-langpack-pl_PL~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-es", rpm:"openoffice.org-langpack-es~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nso_ZA", rpm:"openoffice.org-langpack-nso_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-hi_IN", rpm:"openoffice.org-langpack-hi_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-en", rpm:"openoffice.org-langpack-en~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nl", rpm:"openoffice.org-langpack-nl~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-cs_CZ", rpm:"openoffice.org-langpack-cs_CZ~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-as_IN", rpm:"openoffice.org-langpack-as_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-base", rpm:"openoffice.org-base~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-sk_SK", rpm:"openoffice.org-langpack-sk_SK~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-zh_CN", rpm:"openoffice.org-langpack-zh_CN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-de", rpm:"openoffice.org-langpack-de~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ss_ZA", rpm:"openoffice.org-langpack-ss_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-sdk-doc", rpm:"openoffice.org-sdk-doc~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nr_ZA", rpm:"openoffice.org-langpack-nr_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-kn_IN", rpm:"openoffice.org-langpack-kn_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-zu_ZA", rpm:"openoffice.org-langpack-zu_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-eu_ES", rpm:"openoffice.org-langpack-eu_ES~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-te_IN", rpm:"openoffice.org-langpack-te_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-or_IN", rpm:"openoffice.org-langpack-or_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-cy_GB", rpm:"openoffice.org-langpack-cy_GB~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-mr_IN", rpm:"openoffice.org-langpack-mr_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-he_IL", rpm:"openoffice.org-langpack-he_IL~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-zh_TW", rpm:"openoffice.org-langpack-zh_TW~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-pa_IN", rpm:"openoffice.org-langpack-pa_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ta_IN", rpm:"openoffice.org-langpack-ta_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ms_MY", rpm:"openoffice.org-langpack-ms_MY~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-et_EE", rpm:"openoffice.org-langpack-et_EE~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-base", rpm:"openoffice.org-base~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-sdk", rpm:"openoffice.org-sdk~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nn_NO", rpm:"openoffice.org-langpack-nn_NO~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-headless", rpm:"openoffice.org-headless~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-tr_TR", rpm:"openoffice.org-langpack-tr_TR~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-or_IN", rpm:"openoffice.org-langpack-or_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ms_MY", rpm:"openoffice.org-langpack-ms_MY~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-javafilter", rpm:"openoffice.org-javafilter~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-bn", rpm:"openoffice.org-langpack-bn~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-pt_PT", rpm:"openoffice.org-langpack-pt_PT~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-cs_CZ", rpm:"openoffice.org-langpack-cs_CZ~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-th_TH", rpm:"openoffice.org-langpack-th_TH~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-gl_ES", rpm:"openoffice.org-langpack-gl_ES~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-st_ZA", rpm:"openoffice.org-langpack-st_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-xh_ZA", rpm:"openoffice.org-langpack-xh_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-testtools", rpm:"openoffice.org-testtools~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-es", rpm:"openoffice.org-langpack-es~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ga_IE", rpm:"openoffice.org-langpack-ga_IE~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-hu_HU", rpm:"openoffice.org-langpack-hu_HU~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-sv", rpm:"openoffice.org-langpack-sv~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nl", rpm:"openoffice.org-langpack-nl~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ta_IN", rpm:"openoffice.org-langpack-ta_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-as_IN", rpm:"openoffice.org-langpack-as_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-fr", rpm:"openoffice.org-langpack-fr~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-tn_ZA", rpm:"openoffice.org-langpack-tn_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-hi_IN", rpm:"openoffice.org-langpack-hi_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-pt_BR", rpm:"openoffice.org-langpack-pt_BR~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ur", rpm:"openoffice.org-langpack-ur~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-bg_BG", rpm:"openoffice.org-langpack-bg_BG~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-gu_IN", rpm:"openoffice.org-langpack-gu_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ve_ZA", rpm:"openoffice.org-langpack-ve_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-da_DK", rpm:"openoffice.org-langpack-da_DK~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-el_GR", rpm:"openoffice.org-langpack-el_GR~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ts_ZA", rpm:"openoffice.org-langpack-ts_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-math", rpm:"openoffice.org-math~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ml_IN", rpm:"openoffice.org-langpack-ml_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-zu_ZA", rpm:"openoffice.org-langpack-zu_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-sk_SK", rpm:"openoffice.org-langpack-sk_SK~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-pyuno", rpm:"openoffice.org-pyuno~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ar", rpm:"openoffice.org-langpack-ar~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-it", rpm:"openoffice.org-langpack-it~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-de", rpm:"openoffice.org-langpack-de~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-et_EE", rpm:"openoffice.org-langpack-et_EE~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-core", rpm:"openoffice.org-core~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-sl_SI", rpm:"openoffice.org-langpack-sl_SI~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ko_KR", rpm:"openoffice.org-langpack-ko_KR~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-draw", rpm:"openoffice.org-draw~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-kn_IN", rpm:"openoffice.org-langpack-kn_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-te_IN", rpm:"openoffice.org-langpack-te_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-writer", rpm:"openoffice.org-writer~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-calc", rpm:"openoffice.org-calc~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-impress", rpm:"openoffice.org-impress~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-zh_CN", rpm:"openoffice.org-langpack-zh_CN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ca_ES", rpm:"openoffice.org-langpack-ca_ES~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-debuginfo", rpm:"openoffice.org-debuginfo~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ss_ZA", rpm:"openoffice.org-langpack-ss_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-sdk-doc", rpm:"openoffice.org-sdk-doc~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-sr_CS", rpm:"openoffice.org-langpack-sr_CS~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-xsltfilter", rpm:"openoffice.org-xsltfilter~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-zh_TW", rpm:"openoffice.org-langpack-zh_TW~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-hr_HR", rpm:"openoffice.org-langpack-hr_HR~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-mr_IN", rpm:"openoffice.org-langpack-mr_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-pl_PL", rpm:"openoffice.org-langpack-pl_PL~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-lt_LT", rpm:"openoffice.org-langpack-lt_LT~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nr_ZA", rpm:"openoffice.org-langpack-nr_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-fi_FI", rpm:"openoffice.org-langpack-fi_FI~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-emailmerge", rpm:"openoffice.org-emailmerge~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-he_IL", rpm:"openoffice.org-langpack-he_IL~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nb_NO", rpm:"openoffice.org-langpack-nb_NO~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ru", rpm:"openoffice.org-langpack-ru~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-ja_JP", rpm:"openoffice.org-langpack-ja_JP~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-nso_ZA", rpm:"openoffice.org-langpack-nso_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-graphicfilter", rpm:"openoffice.org-graphicfilter~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-pa_IN", rpm:"openoffice.org-langpack-pa_IN~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-eu_ES", rpm:"openoffice.org-langpack-eu_ES~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-cy_GB", rpm:"openoffice.org-langpack-cy_GB~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-af_ZA", rpm:"openoffice.org-langpack-af_ZA~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-langpack-en", rpm:"openoffice.org-langpack-en~2.3.0~6.5.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
