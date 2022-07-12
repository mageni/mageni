###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for kdegraphics MDKSA-2007:221 (kdegraphics)
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
tag_insight = "Alin Rad Pop found several flaws in how PDF files are handled in kpdf.
  An attacker could create a malicious PDF file that would cause kpdf
  to crash or potentially execute arbitrary code when opened.

  The updated packages have been patched to correct this issue.";

tag_affected = "kdegraphics on Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64,
  Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-11/msg00029.php");
  script_oid("1.3.6.1.4.1.25623.1.0.309051");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:00:25 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDKSA", value: "2007:221");
  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_name( "Mandriva Update for kdegraphics MDKSA-2007:221 (kdegraphics)");

  script_tag(name:"summary", value:"Check for the Version of kdegraphics");
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

  if ((res = isrpmvuln(pkg:"kdegraphics", rpm:"kdegraphics~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-common", rpm:"kdegraphics-common~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kcolorchooser", rpm:"kdegraphics-kcolorchooser~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kcoloredit", rpm:"kdegraphics-kcoloredit~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kdvi", rpm:"kdegraphics-kdvi~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kfax", rpm:"kdegraphics-kfax~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kghostview", rpm:"kdegraphics-kghostview~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kiconedit", rpm:"kdegraphics-kiconedit~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kolourpaint", rpm:"kdegraphics-kolourpaint~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kooka", rpm:"kdegraphics-kooka~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kpdf", rpm:"kdegraphics-kpdf~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kpovmodeler", rpm:"kdegraphics-kpovmodeler~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kruler", rpm:"kdegraphics-kruler~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-ksnapshot", rpm:"kdegraphics-ksnapshot~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-ksvg", rpm:"kdegraphics-ksvg~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kuickshow", rpm:"kdegraphics-kuickshow~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kview", rpm:"kdegraphics-kview~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-mrmlsearch", rpm:"kdegraphics-mrmlsearch~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-common", rpm:"libkdegraphics0-common~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-common-devel", rpm:"libkdegraphics0-common-devel~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kghostview", rpm:"libkdegraphics0-kghostview~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kghostview-devel", rpm:"libkdegraphics0-kghostview-devel~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kooka", rpm:"libkdegraphics0-kooka~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kooka-devel", rpm:"libkdegraphics0-kooka-devel~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kpovmodeler", rpm:"libkdegraphics0-kpovmodeler~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kpovmodeler-devel", rpm:"libkdegraphics0-kpovmodeler-devel~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-ksvg", rpm:"libkdegraphics0-ksvg~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-ksvg-devel", rpm:"libkdegraphics0-ksvg-devel~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kview", rpm:"libkdegraphics0-kview~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kview-devel", rpm:"libkdegraphics0-kview-devel~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-common", rpm:"lib64kdegraphics0-common~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-common-devel", rpm:"lib64kdegraphics0-common-devel~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kghostview", rpm:"lib64kdegraphics0-kghostview~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kghostview-devel", rpm:"lib64kdegraphics0-kghostview-devel~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kooka", rpm:"lib64kdegraphics0-kooka~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kooka-devel", rpm:"lib64kdegraphics0-kooka-devel~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kpovmodeler", rpm:"lib64kdegraphics0-kpovmodeler~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kpovmodeler-devel", rpm:"lib64kdegraphics0-kpovmodeler-devel~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-ksvg", rpm:"lib64kdegraphics0-ksvg~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-ksvg-devel", rpm:"lib64kdegraphics0-ksvg-devel~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kview", rpm:"lib64kdegraphics0-kview~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kview-devel", rpm:"lib64kdegraphics0-kview-devel~3.5.6~1.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"kdegraphics", rpm:"kdegraphics~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-common", rpm:"kdegraphics-common~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kcolorchooser", rpm:"kdegraphics-kcolorchooser~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kcoloredit", rpm:"kdegraphics-kcoloredit~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kdvi", rpm:"kdegraphics-kdvi~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kfax", rpm:"kdegraphics-kfax~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kghostview", rpm:"kdegraphics-kghostview~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kiconedit", rpm:"kdegraphics-kiconedit~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kolourpaint", rpm:"kdegraphics-kolourpaint~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kooka", rpm:"kdegraphics-kooka~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kpdf", rpm:"kdegraphics-kpdf~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kpovmodeler", rpm:"kdegraphics-kpovmodeler~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kruler", rpm:"kdegraphics-kruler~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-ksnapshot", rpm:"kdegraphics-ksnapshot~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-ksvg", rpm:"kdegraphics-ksvg~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kuickshow", rpm:"kdegraphics-kuickshow~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kview", rpm:"kdegraphics-kview~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-mrmlsearch", rpm:"kdegraphics-mrmlsearch~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-common", rpm:"libkdegraphics0-common~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-common-devel", rpm:"libkdegraphics0-common-devel~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kghostview", rpm:"libkdegraphics0-kghostview~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kghostview-devel", rpm:"libkdegraphics0-kghostview-devel~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kooka", rpm:"libkdegraphics0-kooka~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kooka-devel", rpm:"libkdegraphics0-kooka-devel~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kpovmodeler", rpm:"libkdegraphics0-kpovmodeler~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kpovmodeler-devel", rpm:"libkdegraphics0-kpovmodeler-devel~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-ksvg", rpm:"libkdegraphics0-ksvg~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-ksvg-devel", rpm:"libkdegraphics0-ksvg-devel~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kview", rpm:"libkdegraphics0-kview~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kview-devel", rpm:"libkdegraphics0-kview-devel~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-common", rpm:"lib64kdegraphics0-common~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-common-devel", rpm:"lib64kdegraphics0-common-devel~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kghostview", rpm:"lib64kdegraphics0-kghostview~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kghostview-devel", rpm:"lib64kdegraphics0-kghostview-devel~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kooka", rpm:"lib64kdegraphics0-kooka~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kooka-devel", rpm:"lib64kdegraphics0-kooka-devel~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kpovmodeler", rpm:"lib64kdegraphics0-kpovmodeler~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kpovmodeler-devel", rpm:"lib64kdegraphics0-kpovmodeler-devel~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-ksvg", rpm:"lib64kdegraphics0-ksvg~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-ksvg-devel", rpm:"lib64kdegraphics0-ksvg-devel~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kview", rpm:"lib64kdegraphics0-kview~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kview-devel", rpm:"lib64kdegraphics0-kview-devel~3.5.7~8.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
