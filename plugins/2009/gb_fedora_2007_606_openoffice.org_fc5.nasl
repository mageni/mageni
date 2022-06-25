###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for openoffice.org FEDORA-2007-606
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
  requested component (Writer, Calc, Draw, Impress, etc.) from your
  desktop menu. On first start a few files will be installed in the
  user's home, if necessary.
  
  The OpenOffice.org team hopes you enjoy working with OpenOffice.org!";

tag_affected = "openoffice.org on Fedora Core 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-June/msg00542.html");
  script_oid("1.3.6.1.4.1.25623.1.0.308564");
  script_version("$Revision: 6622 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 07:52:50 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:31:39 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2007-606");
  script_cve_id("CVE-2007-0245", "CVE-2007-0239", "CVE-2007-0238", "CVE-2006-2198", "CVE-2006-2199", "CVE-2006-3117");
  script_name( "Fedora Update for openoffice.org FEDORA-2007-606");

  script_tag(name:"summary", value:"Check for the Version of openoffice.org");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora_core", "ssh/login/rpms");
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

if(release == "FC5")
{

  if ((res = isrpmvuln(pkg:"openoffice.org", rpm:"openoffice.org~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-ja_JP", rpm:"i386/openoffice.org-langpack-ja_JP~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-eu_ES", rpm:"i386/openoffice.org-langpack-eu_ES~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-bn_IN", rpm:"i386/openoffice.org-langpack-bn_IN~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-ms_MY", rpm:"i386/openoffice.org-langpack-ms_MY~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-zu_ZA", rpm:"i386/openoffice.org-langpack-zu_ZA~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-nl", rpm:"i386/openoffice.org-langpack-nl~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-fi_FI", rpm:"i386/openoffice.org-langpack-fi_FI~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-lt_LT", rpm:"i386/openoffice.org-langpack-lt_LT~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-impress", rpm:"i386/openoffice.org-impress~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-he_IL", rpm:"i386/openoffice.org-langpack-he_IL~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-pl_PL", rpm:"i386/openoffice.org-langpack-pl_PL~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-emailmerge", rpm:"i386/openoffice.org-emailmerge~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-writer", rpm:"i386/openoffice.org-writer~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-de", rpm:"i386/openoffice.org-langpack-de~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-nn_NO", rpm:"i386/openoffice.org-langpack-nn_NO~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-ar", rpm:"i386/openoffice.org-langpack-ar~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-zh_CN", rpm:"i386/openoffice.org-langpack-zh_CN~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-sk_SK", rpm:"i386/openoffice.org-langpack-sk_SK~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-draw", rpm:"i386/openoffice.org-draw~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-hr_HR", rpm:"i386/openoffice.org-langpack-hr_HR~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-pt_PT", rpm:"i386/openoffice.org-langpack-pt_PT~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-da_DK", rpm:"i386/openoffice.org-langpack-da_DK~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-pyuno", rpm:"i386/openoffice.org-pyuno~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-sv", rpm:"i386/openoffice.org-langpack-sv~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-es", rpm:"i386/openoffice.org-langpack-es~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-gu_IN", rpm:"i386/openoffice.org-langpack-gu_IN~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/openoffice.org-debuginfo", rpm:"i386/debug/openoffice.org-debuginfo~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-calc", rpm:"i386/openoffice.org-calc~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-sr_CS", rpm:"i386/openoffice.org-langpack-sr_CS~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-hu_HU", rpm:"i386/openoffice.org-langpack-hu_HU~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-xsltfilter", rpm:"i386/openoffice.org-xsltfilter~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-it", rpm:"i386/openoffice.org-langpack-it~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-cy_GB", rpm:"i386/openoffice.org-langpack-cy_GB~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-pa_IN", rpm:"i386/openoffice.org-langpack-pa_IN~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-ru", rpm:"i386/openoffice.org-langpack-ru~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-th_TH", rpm:"i386/openoffice.org-langpack-th_TH~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-af_ZA", rpm:"i386/openoffice.org-langpack-af_ZA~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-ta_IN", rpm:"i386/openoffice.org-langpack-ta_IN~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-gl_ES", rpm:"i386/openoffice.org-langpack-gl_ES~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-bg_BG", rpm:"i386/openoffice.org-langpack-bg_BG~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-math", rpm:"i386/openoffice.org-math~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-et_EE", rpm:"i386/openoffice.org-langpack-et_EE~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-base", rpm:"i386/openoffice.org-base~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-fr", rpm:"i386/openoffice.org-langpack-fr~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-ko_KR", rpm:"i386/openoffice.org-langpack-ko_KR~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-testtools", rpm:"i386/openoffice.org-testtools~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-tr_TR", rpm:"i386/openoffice.org-langpack-tr_TR~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-el_GR", rpm:"i386/openoffice.org-langpack-el_GR~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-ca_ES", rpm:"i386/openoffice.org-langpack-ca_ES~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-cs_CZ", rpm:"i386/openoffice.org-langpack-cs_CZ~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-zh_TW", rpm:"i386/openoffice.org-langpack-zh_TW~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-hi_IN", rpm:"i386/openoffice.org-langpack-hi_IN~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-javafilter", rpm:"i386/openoffice.org-javafilter~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-nb_NO", rpm:"i386/openoffice.org-langpack-nb_NO~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-core", rpm:"i386/openoffice.org-core~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-sl_SI", rpm:"i386/openoffice.org-langpack-sl_SI~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-ga_IE", rpm:"i386/openoffice.org-langpack-ga_IE~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-langpack-pt_BR", rpm:"i386/openoffice.org-langpack-pt_BR~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openoffice.org-graphicfilter", rpm:"i386/openoffice.org-graphicfilter~2.0.2~5.22.2", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
