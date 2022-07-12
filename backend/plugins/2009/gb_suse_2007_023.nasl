###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_023.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for OpenOffice_org,libwpd SUSE-SA:2007:023
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
tag_insight = "Several security problems were fixed in the Wordperfect converter library
  libwpd and OpenOffice_org:

  For SUSE Linux 10.1 this aligns the version with the one shipped with
  SUSE Linux Enterprise Desktop 10.

  - CVE-2007-0002: Various problems were fixed in libwpd in OpenOffice_org
  which could be used by remote attackers to potentially execute code
  or crash OpenOffice_org.
  This library is shipped stand-alone in openSUSE 10.2, but included
  in OpenOffice_org packages in previous distributions.

  - CVE-2007-0238: A stack overflow in the StarCalc parser could be
  used by remote attackers to potentially execute code by supplying
  a crafted document. This was reported by NGS Software to the
  OpenOffice team.

  - CVE-2007-0239: A shell quoting problem when opening URLs was fixed
  which could be used by remote attackers to execute code by supplying
  a crafted document and making the user click on an embedded link.

  Also support for the ODF - OpenXML converter was added to the
  OpenOffice_org packages.";

tag_impact = "remote code execution";
tag_affected = "OpenOffice_org,libwpd on SUSE LINUX 10.1, openSUSE 10.2, Novell Linux Desktop 9, SUSE SLED 10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.306477");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-0002", "CVE-2007-0238", "CVE-2007-0239");
  script_name( "SuSE Update for OpenOffice_org,libwpd SUSE-SA:2007:023");

  script_tag(name:"summary", value:"Check for the Version of OpenOffice_org,libwpd");
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

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mono", rpm:"OpenOffice_org-mono~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cs", rpm:"OpenOffice_org-cs~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de", rpm:"OpenOffice_org-de~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-es", rpm:"OpenOffice_org-es~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fr", rpm:"OpenOffice_org-fr~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-galleries", rpm:"OpenOffice_org-galleries~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hu", rpm:"OpenOffice_org-hu~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-it", rpm:"OpenOffice_org-it~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ja", rpm:"OpenOffice_org-ja~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nld", rpm:"OpenOffice_org-nld~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pl", rpm:"OpenOffice_org-pl~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt-BR", rpm:"OpenOffice_org-pt-BR~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sk", rpm:"OpenOffice_org-sk~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-CN", rpm:"OpenOffice_org-zh-CN~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-TW", rpm:"OpenOffice_org-zh-TW~2.0.4~38.2.3", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~2.0.4~38.3", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~2.0.4~38.3", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~2.0.4~38.3", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mono", rpm:"OpenOffice_org-mono~2.0.4~38.3", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-officebean", rpm:"OpenOffice_org-officebean~2.0.4~38.3", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwpd", rpm:"libwpd~0.8.8~4.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwpd-devel", rpm:"libwpd-devel~0.8.8~4.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ar", rpm:"OpenOffice_org-ar~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ca", rpm:"OpenOffice_org-ca~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cs", rpm:"OpenOffice_org-cs~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-da", rpm:"OpenOffice_org-da~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de", rpm:"OpenOffice_org-de~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-el", rpm:"OpenOffice_org-el~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-en", rpm:"OpenOffice_org-en~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-es", rpm:"OpenOffice_org-es~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-et", rpm:"OpenOffice_org-et~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fi", rpm:"OpenOffice_org-fi~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fr", rpm:"OpenOffice_org-fr~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hu", rpm:"OpenOffice_org-hu~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-it", rpm:"OpenOffice_org-it~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ja", rpm:"OpenOffice_org-ja~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ko", rpm:"OpenOffice_org-ko~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nl", rpm:"OpenOffice_org-nl~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pl", rpm:"OpenOffice_org-pl~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt", rpm:"OpenOffice_org-pt~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt-BR", rpm:"OpenOffice_org-pt-BR~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ru", rpm:"OpenOffice_org-ru~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sk", rpm:"OpenOffice_org-sk~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sl", rpm:"OpenOffice_org-sl~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sv", rpm:"OpenOffice_org-sv~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-tr", rpm:"OpenOffice_org-tr~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-CN", rpm:"OpenOffice_org-zh-CN~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-TW", rpm:"OpenOffice_org-zh-TW~1.1.5~0.16", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~1.1~108", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cs", rpm:"OpenOffice_org-cs~1.1~108", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de", rpm:"OpenOffice_org-de~1.1~108", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-en", rpm:"OpenOffice_org-en~1.1~108", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fr", rpm:"OpenOffice_org-fr~1.1~108", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-it", rpm:"OpenOffice_org-it~1.1~108", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nl", rpm:"OpenOffice_org-nl~1.1~108", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-af", rpm:"OpenOffice_org-af~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ar", rpm:"OpenOffice_org-ar~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-be-BY", rpm:"OpenOffice_org-be-BY~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-bg", rpm:"OpenOffice_org-bg~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ca", rpm:"OpenOffice_org-ca~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cs", rpm:"OpenOffice_org-cs~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cy", rpm:"OpenOffice_org-cy~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-da", rpm:"OpenOffice_org-da~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de", rpm:"OpenOffice_org-de~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-el", rpm:"OpenOffice_org-el~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-en-GB", rpm:"OpenOffice_org-en-GB~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-es", rpm:"OpenOffice_org-es~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-et", rpm:"OpenOffice_org-et~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fi", rpm:"OpenOffice_org-fi~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fr", rpm:"OpenOffice_org-fr~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-galleries", rpm:"OpenOffice_org-galleries~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gu-IN", rpm:"OpenOffice_org-gu-IN~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hi-IN", rpm:"OpenOffice_org-hi-IN~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hr", rpm:"OpenOffice_org-hr~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hu", rpm:"OpenOffice_org-hu~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-it", rpm:"OpenOffice_org-it~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ja", rpm:"OpenOffice_org-ja~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-km", rpm:"OpenOffice_org-km~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ko", rpm:"OpenOffice_org-ko~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-lt", rpm:"OpenOffice_org-lt~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mk", rpm:"OpenOffice_org-mk~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mono", rpm:"OpenOffice_org-mono~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nb", rpm:"OpenOffice_org-nb~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nl", rpm:"OpenOffice_org-nl~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nn", rpm:"OpenOffice_org-nn~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-officebean", rpm:"OpenOffice_org-officebean~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pa-IN", rpm:"OpenOffice_org-pa-IN~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pl", rpm:"OpenOffice_org-pl~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt", rpm:"OpenOffice_org-pt~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt-BR", rpm:"OpenOffice_org-pt-BR~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ru", rpm:"OpenOffice_org-ru~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-rw", rpm:"OpenOffice_org-rw~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sk", rpm:"OpenOffice_org-sk~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sl", rpm:"OpenOffice_org-sl~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sr-CS", rpm:"OpenOffice_org-sr-CS~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-st", rpm:"OpenOffice_org-st~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sv", rpm:"OpenOffice_org-sv~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-tr", rpm:"OpenOffice_org-tr~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ts", rpm:"OpenOffice_org-ts~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-vi", rpm:"OpenOffice_org-vi~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-xh", rpm:"OpenOffice_org-xh~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-CN", rpm:"OpenOffice_org-zh-CN~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-TW", rpm:"OpenOffice_org-zh-TW~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zu", rpm:"OpenOffice_org-zu~2.0.4~38.2.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwpd", rpm:"libwpd~0.8.8~4.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwpd-devel", rpm:"libwpd-devel~0.8.8~4.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
