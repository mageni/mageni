###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for kdenetwork4 MDVSA-2010:098 (kdenetwork4)
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
tag_insight = "A vulnerability has been discovered and fixed in kget (kdenetwork4):

  The name attribute of the file element of metalink files is not
  properly sanitized before being used to download files. If a user
  is tricked into downloading from a specially crafted metalink file,
  this can be exploited to download files to directories outside of
  the intended download directory via directory traversal attacks
  (CVE-2010-1000).
  
  Packages for 2009.0 are provided due to the Extended Maintenance
  Program.
  
  The corrected packages solves these problems.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "kdenetwork4 on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2009.1,
  Mandriva Linux 2009.1/X86_64,
  Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-05/msg00022.php");
  script_oid("1.3.6.1.4.1.25623.1.0.313894");
  script_version("$Revision: 8314 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 09:01:01 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-28 10:00:59 +0200 (Fri, 28 May 2010)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_xref(name: "MDVSA", value: "2010:098");
  script_cve_id("CVE-2010-1000");
  script_name("Mandriva Update for kdenetwork4 MDVSA-2010:098 (kdenetwork4)");

  script_tag(name: "summary" , value: "Check for the Version of kdenetwork4");
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

  if ((res = isrpmvuln(pkg:"kde4-filesharing", rpm:"kde4-filesharing~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork4", rpm:"kdenetwork4~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork4-core", rpm:"kdenetwork4-core~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork4-devel", rpm:"kdenetwork4-devel~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork4-kopete-latex", rpm:"kdenetwork4-kopete-latex~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdnssd", rpm:"kdnssd~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kget", rpm:"kget~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kopete", rpm:"kopete~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kppp", rpm:"kppp~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kppp-provider", rpm:"kppp-provider~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krdc", rpm:"krdc~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krfb", rpm:"krfb~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkgetcore4", rpm:"libkgetcore4~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopete4", rpm:"libkopete4~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopeteaddaccountwizard1", rpm:"libkopeteaddaccountwizard1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopetechatwindow_shared1", rpm:"libkopetechatwindow_shared1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopetecontactlist1", rpm:"libkopetecontactlist1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopeteidentity1", rpm:"libkopeteidentity1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopete_oscar4", rpm:"libkopete_oscar4~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopete_otr_shared1", rpm:"libkopete_otr_shared1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopeteprivacy1", rpm:"libkopeteprivacy1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopetestatusmenu1", rpm:"libkopetestatusmenu1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopete_videodevice4", rpm:"libkopete_videodevice4~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkrdccore1", rpm:"libkrdccore1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkyahoo1", rpm:"libkyahoo1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liboscar1", rpm:"liboscar1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kgetcore4", rpm:"lib64kgetcore4~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopete4", rpm:"lib64kopete4~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopeteaddaccountwizard1", rpm:"lib64kopeteaddaccountwizard1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopetechatwindow_shared1", rpm:"lib64kopetechatwindow_shared1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopetecontactlist1", rpm:"lib64kopetecontactlist1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopeteidentity1", rpm:"lib64kopeteidentity1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopete_oscar4", rpm:"lib64kopete_oscar4~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopete_otr_shared1", rpm:"lib64kopete_otr_shared1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopeteprivacy1", rpm:"lib64kopeteprivacy1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopetestatusmenu1", rpm:"lib64kopetestatusmenu1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopete_videodevice4", rpm:"lib64kopete_videodevice4~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64krdccore1", rpm:"lib64krdccore1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kyahoo1", rpm:"lib64kyahoo1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64oscar1", rpm:"lib64oscar1~4.3.5~0.5mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.1")
{

  if ((res = isrpmvuln(pkg:"kde4-filesharing", rpm:"kde4-filesharing~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork4", rpm:"kdenetwork4~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork4-core", rpm:"kdenetwork4-core~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork4-devel", rpm:"kdenetwork4-devel~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork4-kopete-latex", rpm:"kdenetwork4-kopete-latex~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdnssd", rpm:"kdnssd~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kget", rpm:"kget~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kopete", rpm:"kopete~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kppp", rpm:"kppp~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kppp-provider", rpm:"kppp-provider~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krdc", rpm:"krdc~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krfb", rpm:"krfb~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgadu_kopete1", rpm:"libgadu_kopete1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libiris_kopete1", rpm:"libiris_kopete1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkgetcore4", rpm:"libkgetcore4~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopete4", rpm:"libkopete4~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopeteaddaccountwizard1", rpm:"libkopeteaddaccountwizard1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopetechatwindow_shared1", rpm:"libkopetechatwindow_shared1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopeteidentity1", rpm:"libkopeteidentity1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopete_oscar4", rpm:"libkopete_oscar4~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopete_otr_shared1", rpm:"libkopete_otr_shared1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopeteprivacy1", rpm:"libkopeteprivacy1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopetestatusmenu1", rpm:"libkopetestatusmenu1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopete_videodevice4", rpm:"libkopete_videodevice4~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkyahoo1", rpm:"libkyahoo1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liboscar1", rpm:"liboscar1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gadu_kopete1", rpm:"lib64gadu_kopete1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64iris_kopete1", rpm:"lib64iris_kopete1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kgetcore4", rpm:"lib64kgetcore4~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopete4", rpm:"lib64kopete4~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopeteaddaccountwizard1", rpm:"lib64kopeteaddaccountwizard1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopetechatwindow_shared1", rpm:"lib64kopetechatwindow_shared1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopeteidentity1", rpm:"lib64kopeteidentity1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopete_oscar4", rpm:"lib64kopete_oscar4~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopete_otr_shared1", rpm:"lib64kopete_otr_shared1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopeteprivacy1", rpm:"lib64kopeteprivacy1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopetestatusmenu1", rpm:"lib64kopetestatusmenu1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopete_videodevice4", rpm:"lib64kopete_videodevice4~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kyahoo1", rpm:"lib64kyahoo1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64oscar1", rpm:"lib64oscar1~4.2.4~0.4mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"kde4-filesharing", rpm:"kde4-filesharing~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork4", rpm:"kdenetwork4~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork4-core", rpm:"kdenetwork4-core~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork4-devel", rpm:"kdenetwork4-devel~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdenetwork4-kopete-latex", rpm:"kdenetwork4-kopete-latex~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdnssd", rpm:"kdnssd~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kget", rpm:"kget~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kopete", rpm:"kopete~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kppp", rpm:"kppp~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kppp-provider", rpm:"kppp-provider~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krdc", rpm:"krdc~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krfb", rpm:"krfb~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgadu_kopete1", rpm:"libgadu_kopete1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libiris_kopete1", rpm:"libiris_kopete1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkgetcore4", rpm:"libkgetcore4~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopete4", rpm:"libkopete4~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopeteaddaccountwizard1", rpm:"libkopeteaddaccountwizard1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopetechatwindow_shared1", rpm:"libkopetechatwindow_shared1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopeteidentity1", rpm:"libkopeteidentity1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopete_oscar4", rpm:"libkopete_oscar4~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopete_otr_shared1", rpm:"libkopete_otr_shared1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopeteprivacy1", rpm:"libkopeteprivacy1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopetestatusmenu1", rpm:"libkopetestatusmenu1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkopete_videodevice4", rpm:"libkopete_videodevice4~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkyahoo1", rpm:"libkyahoo1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liboscar1", rpm:"liboscar1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gadu_kopete1", rpm:"lib64gadu_kopete1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64iris_kopete1", rpm:"lib64iris_kopete1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kgetcore4", rpm:"lib64kgetcore4~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopete4", rpm:"lib64kopete4~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopeteaddaccountwizard1", rpm:"lib64kopeteaddaccountwizard1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopetechatwindow_shared1", rpm:"lib64kopetechatwindow_shared1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopeteidentity1", rpm:"lib64kopeteidentity1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopete_oscar4", rpm:"lib64kopete_oscar4~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopete_otr_shared1", rpm:"lib64kopete_otr_shared1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopeteprivacy1", rpm:"lib64kopeteprivacy1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopetestatusmenu1", rpm:"lib64kopetestatusmenu1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kopete_videodevice4", rpm:"lib64kopete_videodevice4~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kyahoo1", rpm:"lib64kyahoo1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64oscar1", rpm:"lib64oscar1~4.2.4~0.8mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
