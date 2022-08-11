###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for koffice MDKSA-2007:222 (koffice)
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
tag_insight = "Alin Rad Pop found several flaws in how PDF files are handled
  in koffice.  An attacker could create a malicious PDF file that
  would cause koffice to crash or potentially execute arbitrary code
  when opened.

  The updated packages have been patched to correct this issue.";

tag_affected = "koffice on Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64,
  Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-11/msg00030.php");
  script_oid("1.3.6.1.4.1.25623.1.0.305878");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:00:25 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDKSA", value: "2007:222");
  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_name( "Mandriva Update for koffice MDKSA-2007:222 (koffice)");

  script_tag(name:"summary", value:"Check for the Version of koffice");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2007.1")
{

  if ((res = isrpmvuln(pkg:"koffice", rpm:"koffice~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-karbon", rpm:"koffice-karbon~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-kexi", rpm:"koffice-kexi~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-kformula", rpm:"koffice-kformula~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-kivio", rpm:"koffice-kivio~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-koshell", rpm:"koffice-koshell~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-kplato", rpm:"koffice-kplato~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-kpresenter", rpm:"koffice-kpresenter~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-krita", rpm:"koffice-krita~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-kspread", rpm:"koffice-kspread~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-kugar", rpm:"koffice-kugar~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-kword", rpm:"koffice-kword~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-progs", rpm:"koffice-progs~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-karbon", rpm:"libkoffice2-karbon~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-karbon-devel", rpm:"libkoffice2-karbon-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kexi", rpm:"libkoffice2-kexi~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kexi-devel", rpm:"libkoffice2-kexi-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kformula", rpm:"libkoffice2-kformula~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kformula-devel", rpm:"libkoffice2-kformula-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kivio", rpm:"libkoffice2-kivio~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kivio-devel", rpm:"libkoffice2-kivio-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-koshell", rpm:"libkoffice2-koshell~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kplato", rpm:"libkoffice2-kplato~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kpresenter", rpm:"libkoffice2-kpresenter~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kpresenter-devel", rpm:"libkoffice2-kpresenter-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-krita", rpm:"libkoffice2-krita~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-krita-devel", rpm:"libkoffice2-krita-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kspread", rpm:"libkoffice2-kspread~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kspread-devel", rpm:"libkoffice2-kspread-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kugar", rpm:"libkoffice2-kugar~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kugar-devel", rpm:"libkoffice2-kugar-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kword", rpm:"libkoffice2-kword~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kword-devel", rpm:"libkoffice2-kword-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-progs", rpm:"libkoffice2-progs~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-progs-devel", rpm:"libkoffice2-progs-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-karbon", rpm:"lib64koffice2-karbon~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-karbon-devel", rpm:"lib64koffice2-karbon-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kexi", rpm:"lib64koffice2-kexi~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kexi-devel", rpm:"lib64koffice2-kexi-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kformula", rpm:"lib64koffice2-kformula~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kformula-devel", rpm:"lib64koffice2-kformula-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kivio", rpm:"lib64koffice2-kivio~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kivio-devel", rpm:"lib64koffice2-kivio-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-koshell", rpm:"lib64koffice2-koshell~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kplato", rpm:"lib64koffice2-kplato~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kpresenter", rpm:"lib64koffice2-kpresenter~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kpresenter-devel", rpm:"lib64koffice2-kpresenter-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-krita", rpm:"lib64koffice2-krita~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-krita-devel", rpm:"lib64koffice2-krita-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kspread", rpm:"lib64koffice2-kspread~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kspread-devel", rpm:"lib64koffice2-kspread-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kugar", rpm:"lib64koffice2-kugar~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kugar-devel", rpm:"lib64koffice2-kugar-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kword", rpm:"lib64koffice2-kword~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kword-devel", rpm:"lib64koffice2-kword-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-progs", rpm:"lib64koffice2-progs~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-progs-devel", rpm:"lib64koffice2-progs-devel~1.6.2~2.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"koffice", rpm:"koffice~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-karbon", rpm:"koffice-karbon~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-kexi", rpm:"koffice-kexi~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-kformula", rpm:"koffice-kformula~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-kivio", rpm:"koffice-kivio~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-koshell", rpm:"koffice-koshell~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-kplato", rpm:"koffice-kplato~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-kpresenter", rpm:"koffice-kpresenter~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-krita", rpm:"koffice-krita~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-kspread", rpm:"koffice-kspread~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-kugar", rpm:"koffice-kugar~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-kword", rpm:"koffice-kword~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"koffice-progs", rpm:"koffice-progs~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-karbon", rpm:"libkoffice2-karbon~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-karbon-devel", rpm:"libkoffice2-karbon-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kexi", rpm:"libkoffice2-kexi~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kexi-devel", rpm:"libkoffice2-kexi-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kformula", rpm:"libkoffice2-kformula~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kformula-devel", rpm:"libkoffice2-kformula-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kivio", rpm:"libkoffice2-kivio~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kivio-devel", rpm:"libkoffice2-kivio-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-koshell", rpm:"libkoffice2-koshell~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kplato", rpm:"libkoffice2-kplato~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kpresenter", rpm:"libkoffice2-kpresenter~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kpresenter-devel", rpm:"libkoffice2-kpresenter-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-krita", rpm:"libkoffice2-krita~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-krita-devel", rpm:"libkoffice2-krita-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kspread", rpm:"libkoffice2-kspread~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kspread-devel", rpm:"libkoffice2-kspread-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kugar", rpm:"libkoffice2-kugar~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kugar-devel", rpm:"libkoffice2-kugar-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kword", rpm:"libkoffice2-kword~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-kword-devel", rpm:"libkoffice2-kword-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-progs", rpm:"libkoffice2-progs~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkoffice2-progs-devel", rpm:"libkoffice2-progs-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-karbon", rpm:"lib64koffice2-karbon~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-karbon-devel", rpm:"lib64koffice2-karbon-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kexi", rpm:"lib64koffice2-kexi~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kexi-devel", rpm:"lib64koffice2-kexi-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kformula", rpm:"lib64koffice2-kformula~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kformula-devel", rpm:"lib64koffice2-kformula-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kivio", rpm:"lib64koffice2-kivio~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kivio-devel", rpm:"lib64koffice2-kivio-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-koshell", rpm:"lib64koffice2-koshell~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kplato", rpm:"lib64koffice2-kplato~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kpresenter", rpm:"lib64koffice2-kpresenter~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kpresenter-devel", rpm:"lib64koffice2-kpresenter-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-krita", rpm:"lib64koffice2-krita~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-krita-devel", rpm:"lib64koffice2-krita-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kspread", rpm:"lib64koffice2-kspread~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kspread-devel", rpm:"lib64koffice2-kspread-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kugar", rpm:"lib64koffice2-kugar~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kugar-devel", rpm:"lib64koffice2-kugar-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kword", rpm:"lib64koffice2-kword~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-kword-devel", rpm:"lib64koffice2-kword-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-progs", rpm:"lib64koffice2-progs~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64koffice2-progs-devel", rpm:"lib64koffice2-progs-devel~1.6.3~9.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
