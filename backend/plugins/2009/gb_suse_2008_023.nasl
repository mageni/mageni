###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2008_023.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for OpenOffice_org SUSE-SA:2008:023
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
tag_insight = "This update of OpenOffice fixes various critical security vulnerabilities
  - heap-overflow when parsing PPT files CVE-2008-0320
  - various buffer-overflows while parsing QPRO files CVE-2007-5745,
  CVE-2007-5747 (NLD9 not affected)
  - integer overflow while parsing EMF files CVE-2007-5746
  - out-of-bound memory access and a heap-overflow in the regex engine
  of libICU CVE-2007-4771 (NLD9 not affected)

  These vulnerabilities can only by exploited remotely with user-assistance
  and in conjunction with other software receiving OOo documents over
  the network (like a kmail attachment).

  Please note that users of SLED10-SP1 that installed the OOo-2.4 update
  already have the fixes.";

tag_impact = "local privilege escalation";
tag_affected = "OpenOffice_org on SUSE LINUX 10.1, openSUSE 10.2, openSUSE 10.3, Novell Linux Desktop 9, SUSE Linux Enterprise Desktop 10 SP1, SLE SDK 10 SP1";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.305819");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-0320", "CVE-2007-5747", "CVE-2007-5746", "CVE-2007-5745", "CVE-2007-4771", "CVE-2007-4770");
  script_name( "SuSE Update for OpenOffice_org SUSE-SA:2008:023");

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

if(release == "openSUSE10.3")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-base", rpm:"OpenOffice_org-base~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-calc", rpm:"OpenOffice_org-calc~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-devel", rpm:"OpenOffice_org-devel~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-draw", rpm:"OpenOffice_org-draw~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-filters", rpm:"OpenOffice_org-filters~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-impress", rpm:"OpenOffice_org-impress~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mailmerge", rpm:"OpenOffice_org-mailmerge~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-math", rpm:"OpenOffice_org-math~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mono", rpm:"OpenOffice_org-mono~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-officebean", rpm:"OpenOffice_org-officebean~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pyuno", rpm:"OpenOffice_org-pyuno~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sdk", rpm:"OpenOffice_org-sdk~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sdk-doc", rpm:"OpenOffice_org-sdk-doc~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-testtool", rpm:"OpenOffice_org-testtool~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-writer", rpm:"OpenOffice_org-writer~2.3.0.1.2~10.5", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-af", rpm:"OpenOffice_org-af~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ar", rpm:"OpenOffice_org-ar~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-be-BY", rpm:"OpenOffice_org-be-BY~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-bg", rpm:"OpenOffice_org-bg~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ca", rpm:"OpenOffice_org-ca~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cs", rpm:"OpenOffice_org-cs~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cy", rpm:"OpenOffice_org-cy~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-da", rpm:"OpenOffice_org-da~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de", rpm:"OpenOffice_org-de~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-el", rpm:"OpenOffice_org-el~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-en-GB", rpm:"OpenOffice_org-en-GB~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-es", rpm:"OpenOffice_org-es~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-et", rpm:"OpenOffice_org-et~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fi", rpm:"OpenOffice_org-fi~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fr", rpm:"OpenOffice_org-fr~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-galleries", rpm:"OpenOffice_org-galleries~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gu-IN", rpm:"OpenOffice_org-gu-IN~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hi-IN", rpm:"OpenOffice_org-hi-IN~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hr", rpm:"OpenOffice_org-hr~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hu", rpm:"OpenOffice_org-hu~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-it", rpm:"OpenOffice_org-it~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ja", rpm:"OpenOffice_org-ja~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-km", rpm:"OpenOffice_org-km~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ko", rpm:"OpenOffice_org-ko~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-lt", rpm:"OpenOffice_org-lt~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mk", rpm:"OpenOffice_org-mk~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mono", rpm:"OpenOffice_org-mono~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nb", rpm:"OpenOffice_org-nb~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nl", rpm:"OpenOffice_org-nl~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nn", rpm:"OpenOffice_org-nn~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-officebean", rpm:"OpenOffice_org-officebean~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pa-IN", rpm:"OpenOffice_org-pa-IN~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pl", rpm:"OpenOffice_org-pl~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt", rpm:"OpenOffice_org-pt~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt-BR", rpm:"OpenOffice_org-pt-BR~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ru", rpm:"OpenOffice_org-ru~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-rw", rpm:"OpenOffice_org-rw~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sdk", rpm:"OpenOffice_org-sdk~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sdk-doc", rpm:"OpenOffice_org-sdk-doc~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sk", rpm:"OpenOffice_org-sk~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sl", rpm:"OpenOffice_org-sl~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sr-CS", rpm:"OpenOffice_org-sr-CS~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-st", rpm:"OpenOffice_org-st~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sv", rpm:"OpenOffice_org-sv~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-tr", rpm:"OpenOffice_org-tr~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ts", rpm:"OpenOffice_org-ts~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-vi", rpm:"OpenOffice_org-vi~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-xh", rpm:"OpenOffice_org-xh~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-CN", rpm:"OpenOffice_org-zh-CN~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-TW", rpm:"OpenOffice_org-zh-TW~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zu", rpm:"OpenOffice_org-zu~2.0.4~38.12", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDK10SP1")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cs", rpm:"OpenOffice_org-cs~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de", rpm:"OpenOffice_org-de~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-es", rpm:"OpenOffice_org-es~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fr", rpm:"OpenOffice_org-fr~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-galleries", rpm:"OpenOffice_org-galleries~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hu", rpm:"OpenOffice_org-hu~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-it", rpm:"OpenOffice_org-it~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ja", rpm:"OpenOffice_org-ja~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mono", rpm:"OpenOffice_org-mono~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pl", rpm:"OpenOffice_org-pl~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt-BR", rpm:"OpenOffice_org-pt-BR~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sk", rpm:"OpenOffice_org-sk~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-CN", rpm:"OpenOffice_org-zh-CN~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-TW", rpm:"OpenOffice_org-zh-TW~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-af", rpm:"OpenOffice_org-af~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ar", rpm:"OpenOffice_org-ar~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ca", rpm:"OpenOffice_org-ca~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-da", rpm:"OpenOffice_org-da~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fi", rpm:"OpenOffice_org-fi~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gu-IN", rpm:"OpenOffice_org-gu-IN~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hi-IN", rpm:"OpenOffice_org-hi-IN~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nb", rpm:"OpenOffice_org-nb~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nl", rpm:"OpenOffice_org-nl~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nld", rpm:"OpenOffice_org-nld~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nn", rpm:"OpenOffice_org-nn~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ru", rpm:"OpenOffice_org-ru~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sv", rpm:"OpenOffice_org-sv~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-xh", rpm:"OpenOffice_org-xh~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zu", rpm:"OpenOffice_org-zu~2.4~0.2.11", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ar", rpm:"OpenOffice_org-ar~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ca", rpm:"OpenOffice_org-ca~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cs", rpm:"OpenOffice_org-cs~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-da", rpm:"OpenOffice_org-da~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de", rpm:"OpenOffice_org-de~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-el", rpm:"OpenOffice_org-el~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-en", rpm:"OpenOffice_org-en~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-en-help", rpm:"OpenOffice_org-en-help~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-es", rpm:"OpenOffice_org-es~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-et", rpm:"OpenOffice_org-et~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fi", rpm:"OpenOffice_org-fi~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fr", rpm:"OpenOffice_org-fr~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hu", rpm:"OpenOffice_org-hu~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-it", rpm:"OpenOffice_org-it~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ja", rpm:"OpenOffice_org-ja~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ko", rpm:"OpenOffice_org-ko~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nl", rpm:"OpenOffice_org-nl~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pl", rpm:"OpenOffice_org-pl~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt", rpm:"OpenOffice_org-pt~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt-BR", rpm:"OpenOffice_org-pt-BR~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ru", rpm:"OpenOffice_org-ru~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sk", rpm:"OpenOffice_org-sk~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sl", rpm:"OpenOffice_org-sl~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sv", rpm:"OpenOffice_org-sv~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-tr", rpm:"OpenOffice_org-tr~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-CN", rpm:"OpenOffice_org-zh-CN~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-TW", rpm:"OpenOffice_org-zh-TW~1.1.5~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP1")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cs", rpm:"OpenOffice_org-cs~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de", rpm:"OpenOffice_org-de~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-es", rpm:"OpenOffice_org-es~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fr", rpm:"OpenOffice_org-fr~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-galleries", rpm:"OpenOffice_org-galleries~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hu", rpm:"OpenOffice_org-hu~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-it", rpm:"OpenOffice_org-it~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ja", rpm:"OpenOffice_org-ja~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mono", rpm:"OpenOffice_org-mono~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pl", rpm:"OpenOffice_org-pl~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt-BR", rpm:"OpenOffice_org-pt-BR~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sk", rpm:"OpenOffice_org-sk~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-CN", rpm:"OpenOffice_org-zh-CN~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-TW", rpm:"OpenOffice_org-zh-TW~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-af", rpm:"OpenOffice_org-af~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ar", rpm:"OpenOffice_org-ar~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ca", rpm:"OpenOffice_org-ca~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-da", rpm:"OpenOffice_org-da~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fi", rpm:"OpenOffice_org-fi~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gu-IN", rpm:"OpenOffice_org-gu-IN~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hi-IN", rpm:"OpenOffice_org-hi-IN~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nb", rpm:"OpenOffice_org-nb~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nl", rpm:"OpenOffice_org-nl~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nld", rpm:"OpenOffice_org-nld~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nn", rpm:"OpenOffice_org-nn~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ru", rpm:"OpenOffice_org-ru~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sv", rpm:"OpenOffice_org-sv~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-xh", rpm:"OpenOffice_org-xh~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zu", rpm:"OpenOffice_org-zu~2.4~0.2.11", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-af", rpm:"OpenOffice_org-af~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ar", rpm:"OpenOffice_org-ar~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-be-BY", rpm:"OpenOffice_org-be-BY~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-bg", rpm:"OpenOffice_org-bg~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ca", rpm:"OpenOffice_org-ca~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cs", rpm:"OpenOffice_org-cs~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cy", rpm:"OpenOffice_org-cy~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-da", rpm:"OpenOffice_org-da~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de", rpm:"OpenOffice_org-de~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-el", rpm:"OpenOffice_org-el~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-en-GB", rpm:"OpenOffice_org-en-GB~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-es", rpm:"OpenOffice_org-es~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-et", rpm:"OpenOffice_org-et~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fi", rpm:"OpenOffice_org-fi~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fr", rpm:"OpenOffice_org-fr~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-galleries", rpm:"OpenOffice_org-galleries~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gu-IN", rpm:"OpenOffice_org-gu-IN~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hi-IN", rpm:"OpenOffice_org-hi-IN~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hr", rpm:"OpenOffice_org-hr~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hu", rpm:"OpenOffice_org-hu~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-it", rpm:"OpenOffice_org-it~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ja", rpm:"OpenOffice_org-ja~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-km", rpm:"OpenOffice_org-km~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ko", rpm:"OpenOffice_org-ko~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-lt", rpm:"OpenOffice_org-lt~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mk", rpm:"OpenOffice_org-mk~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mono", rpm:"OpenOffice_org-mono~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nb", rpm:"OpenOffice_org-nb~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nl", rpm:"OpenOffice_org-nl~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nn", rpm:"OpenOffice_org-nn~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-officebean", rpm:"OpenOffice_org-officebean~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pa-IN", rpm:"OpenOffice_org-pa-IN~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pl", rpm:"OpenOffice_org-pl~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt", rpm:"OpenOffice_org-pt~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt-BR", rpm:"OpenOffice_org-pt-BR~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ru", rpm:"OpenOffice_org-ru~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-rw", rpm:"OpenOffice_org-rw~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sk", rpm:"OpenOffice_org-sk~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sl", rpm:"OpenOffice_org-sl~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sr-CS", rpm:"OpenOffice_org-sr-CS~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-st", rpm:"OpenOffice_org-st~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sv", rpm:"OpenOffice_org-sv~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-tr", rpm:"OpenOffice_org-tr~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ts", rpm:"OpenOffice_org-ts~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-vi", rpm:"OpenOffice_org-vi~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-xh", rpm:"OpenOffice_org-xh~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-CN", rpm:"OpenOffice_org-zh-CN~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-TW", rpm:"OpenOffice_org-zh-TW~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zu", rpm:"OpenOffice_org-zu~2.0.4~38.9", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
