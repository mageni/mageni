###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_001.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for OpenOffice_org SUSE-SA:2007:001
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
tag_insight = "Security problems were fixed in the WMF and Enhanced WMF handling
  in OpenOffice_org These could potentially be used to execute code
  or crash OpenOffice when a user could be convinced to open specially
  crafted document (for instance a document sent by E-mail).

  This issue is tracked by the Mitre CVE ID CVE-2006-5870.

  openSUSE 10.2 is not affected by this problem, it already contains
  the fixed OpenOffice_org 2.1 version.

  Additionally the OpenOffice_org 2.0 version in SLED 10 was fitted with
  hooks to add OfficeXML support with a later update.

  Due to the very large size of this update and mirror lag it might
  take some hours or days until the updates are available on our mirrors.";

tag_impact = "code execution";
tag_affected = "OpenOffice_org on Novell Linux Desktop 9, SUSE LINUX 10.1, SUSE SLED 10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.309001");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2006-5870");
  script_name( "SuSE Update for OpenOffice_org SUSE-SA:2007:001");

  script_tag(name:"summary", value:"Check for the Version of OpenOffice_org");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "impact" , value : tag_impact);
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

if(release == "SLED10")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mono", rpm:"OpenOffice_org-mono~2.0.2~27.15", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~2.0.2~27.15", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~2.0.2~27.15", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~2.0.2~27.15", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ar", rpm:"OpenOffice_org-ar~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ca", rpm:"OpenOffice_org-ca~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cs", rpm:"OpenOffice_org-cs~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-da", rpm:"OpenOffice_org-da~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de", rpm:"OpenOffice_org-de~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-el", rpm:"OpenOffice_org-el~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-en", rpm:"OpenOffice_org-en~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-es", rpm:"OpenOffice_org-es~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-et", rpm:"OpenOffice_org-et~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fi", rpm:"OpenOffice_org-fi~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fr", rpm:"OpenOffice_org-fr~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hu", rpm:"OpenOffice_org-hu~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-it", rpm:"OpenOffice_org-it~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ja", rpm:"OpenOffice_org-ja~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ko", rpm:"OpenOffice_org-ko~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nl", rpm:"OpenOffice_org-nl~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pl", rpm:"OpenOffice_org-pl~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt", rpm:"OpenOffice_org-pt~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt-BR", rpm:"OpenOffice_org-pt-BR~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ru", rpm:"OpenOffice_org-ru~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sk", rpm:"OpenOffice_org-sk~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sl", rpm:"OpenOffice_org-sl~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sv", rpm:"OpenOffice_org-sv~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-tr", rpm:"OpenOffice_org-tr~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-CN", rpm:"OpenOffice_org-zh-CN~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-TW", rpm:"OpenOffice_org-zh-TW~1.1.5~0.13", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~1.1~105", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cs", rpm:"OpenOffice_org-cs~1.1~105", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de", rpm:"OpenOffice_org-de~1.1~105", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-en", rpm:"OpenOffice_org-en~1.1~105", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fr", rpm:"OpenOffice_org-fr~1.1~105", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-it", rpm:"OpenOffice_org-it~1.1~105", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nl", rpm:"OpenOffice_org-nl~1.1~105", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~2.0.2~27.15", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~2.0.2~27.15", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~2.0.2~27.15", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mono", rpm:"OpenOffice_org-mono~2.0.2~27.15", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-officebean", rpm:"OpenOffice_org-officebean~2.0.2~27.15", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
