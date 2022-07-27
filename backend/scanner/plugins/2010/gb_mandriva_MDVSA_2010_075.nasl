###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for openoffice.org MDVSA-2010:075 (openoffice.org)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "This updates provides a security update to the OpenOffice.org described
  as follow:

  OpenOffice's xmlsec uses a bundled Libtool which might load .la
  file in the current working directory allowing local users to gain
  privileges via a Trojan horse file. For enabling such vulnerability
  xmlsec has to use --enable-crypto_dl building flag however it does
  not, although the fix keeps protected against this threat whenever
  that flag had been enabled (CVE-2009-3736).
  
  Addittionaly this update provides following bug fixes:
  
  OpenOffice.org is not properly configure to use the xdg-email
  functionality of the FreeDesktop standard (#52195).
  
  Template desktop icons are not properly set up then they are not
  presented under the context menu of applications like Dolphin (#56439).
  
  libia_ora-gnome is added as suggest as long as that package is needed
  for a better look (#57385#c28).
  
  It is enabled a fallback logic to properly select an OpenOffice.org
  style whenever one is set up but that is not installed (#57530#c1,
  #53284, #45133, #39043)
  
  It is enabled the Firefox plugin for viewing OpenOffice.org documents
  inside browser.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "openoffice.org on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-04/msg00016.php");
  script_oid("1.3.6.1.4.1.25623.1.0.314905");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-16 17:02:11 +0200 (Fri, 16 Apr 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2010:075");
  script_cve_id("CVE-2009-3736");
  script_name("Mandriva Update for openoffice.org MDVSA-2010:075 (openoffice.org)");

  script_tag(name: "summary" , value: "Check for the Version of openoffice.org");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"openoffice.org", rpm:"openoffice.org~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-base", rpm:"openoffice.org-base~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-calc", rpm:"openoffice.org-calc~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-common", rpm:"openoffice.org-common~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-core", rpm:"openoffice.org-core~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-devel", rpm:"openoffice.org-devel~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-devel-doc", rpm:"openoffice.org-devel-doc~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-draw", rpm:"openoffice.org-draw~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-filter-binfilter", rpm:"openoffice.org-filter-binfilter~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-gnome", rpm:"openoffice.org-gnome~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-af", rpm:"openoffice.org-help-af~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ar", rpm:"openoffice.org-help-ar~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-bg", rpm:"openoffice.org-help-bg~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-br", rpm:"openoffice.org-help-br~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-bs", rpm:"openoffice.org-help-bs~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ca", rpm:"openoffice.org-help-ca~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-cs", rpm:"openoffice.org-help-cs~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-cy", rpm:"openoffice.org-help-cy~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-da", rpm:"openoffice.org-help-da~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-de", rpm:"openoffice.org-help-de~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-el", rpm:"openoffice.org-help-el~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-en_GB", rpm:"openoffice.org-help-en_GB~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-en_US", rpm:"openoffice.org-help-en_US~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-es", rpm:"openoffice.org-help-es~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-et", rpm:"openoffice.org-help-et~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-eu", rpm:"openoffice.org-help-eu~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-fi", rpm:"openoffice.org-help-fi~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-fr", rpm:"openoffice.org-help-fr~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-he", rpm:"openoffice.org-help-he~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-hi", rpm:"openoffice.org-help-hi~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-hu", rpm:"openoffice.org-help-hu~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-it", rpm:"openoffice.org-help-it~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ja", rpm:"openoffice.org-help-ja~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ko", rpm:"openoffice.org-help-ko~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-mk", rpm:"openoffice.org-help-mk~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-nb", rpm:"openoffice.org-help-nb~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-nl", rpm:"openoffice.org-help-nl~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-nn", rpm:"openoffice.org-help-nn~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-pl", rpm:"openoffice.org-help-pl~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-pt", rpm:"openoffice.org-help-pt~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-pt_BR", rpm:"openoffice.org-help-pt_BR~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ru", rpm:"openoffice.org-help-ru~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-sk", rpm:"openoffice.org-help-sk~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-sl", rpm:"openoffice.org-help-sl~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-sv", rpm:"openoffice.org-help-sv~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ta", rpm:"openoffice.org-help-ta~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-tr", rpm:"openoffice.org-help-tr~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-zh_CN", rpm:"openoffice.org-help-zh_CN~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-zh_TW", rpm:"openoffice.org-help-zh_TW~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-zu", rpm:"openoffice.org-help-zu~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-impress", rpm:"openoffice.org-impress~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-java-common", rpm:"openoffice.org-java-common~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-af", rpm:"openoffice.org-l10n-af~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ar", rpm:"openoffice.org-l10n-ar~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-bg", rpm:"openoffice.org-l10n-bg~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-br", rpm:"openoffice.org-l10n-br~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-bs", rpm:"openoffice.org-l10n-bs~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ca", rpm:"openoffice.org-l10n-ca~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-cs", rpm:"openoffice.org-l10n-cs~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-cy", rpm:"openoffice.org-l10n-cy~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-da", rpm:"openoffice.org-l10n-da~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-de", rpm:"openoffice.org-l10n-de~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-el", rpm:"openoffice.org-l10n-el~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-en_GB", rpm:"openoffice.org-l10n-en_GB~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-es", rpm:"openoffice.org-l10n-es~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-et", rpm:"openoffice.org-l10n-et~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-eu", rpm:"openoffice.org-l10n-eu~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-fi", rpm:"openoffice.org-l10n-fi~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-fr", rpm:"openoffice.org-l10n-fr~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-he", rpm:"openoffice.org-l10n-he~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-hi", rpm:"openoffice.org-l10n-hi~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-hu", rpm:"openoffice.org-l10n-hu~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-it", rpm:"openoffice.org-l10n-it~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ja", rpm:"openoffice.org-l10n-ja~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ko", rpm:"openoffice.org-l10n-ko~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-mk", rpm:"openoffice.org-l10n-mk~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-nb", rpm:"openoffice.org-l10n-nb~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-nl", rpm:"openoffice.org-l10n-nl~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-nn", rpm:"openoffice.org-l10n-nn~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-pl", rpm:"openoffice.org-l10n-pl~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-pt", rpm:"openoffice.org-l10n-pt~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-pt_BR", rpm:"openoffice.org-l10n-pt_BR~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ru", rpm:"openoffice.org-l10n-ru~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-sk", rpm:"openoffice.org-l10n-sk~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-sl", rpm:"openoffice.org-l10n-sl~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-sv", rpm:"openoffice.org-l10n-sv~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ta", rpm:"openoffice.org-l10n-ta~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-tr", rpm:"openoffice.org-l10n-tr~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-zh_CN", rpm:"openoffice.org-l10n-zh_CN~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-zh_TW", rpm:"openoffice.org-l10n-zh_TW~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-zu", rpm:"openoffice.org-l10n-zu~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-math", rpm:"openoffice.org-math~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-mono", rpm:"openoffice.org-mono~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-openclipart", rpm:"openoffice.org-openclipart~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-pdfimport", rpm:"openoffice.org-pdfimport~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-presentation-minimizer", rpm:"openoffice.org-presentation-minimizer~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-presenter-screen", rpm:"openoffice.org-presenter-screen~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-pyuno", rpm:"openoffice.org-pyuno~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-style-crystal", rpm:"openoffice.org-style-crystal~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-style-galaxy", rpm:"openoffice.org-style-galaxy~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-style-hicontrast", rpm:"openoffice.org-style-hicontrast~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-style-industrial", rpm:"openoffice.org-style-industrial~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-style-tango", rpm:"openoffice.org-style-tango~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-testtool", rpm:"openoffice.org-testtool~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-wiki-publisher", rpm:"openoffice.org-wiki-publisher~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-writer", rpm:"openoffice.org-writer~3.1.1~2.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
