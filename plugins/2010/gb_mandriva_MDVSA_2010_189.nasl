###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for pcsc-lite MDVSA-2010:189 (pcsc-lite)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in pcsc-lite:

  The MSGFunctionDemarshall function in winscard_svc.c in the PC/SC Smart
  Card daemon (aka PCSCD) in MUSCLE PCSC-Lite before 1.5.4 might allow
  local users to cause a denial of service (daemon crash) via crafted
  SCARD_SET_ATTRIB message data, which is improperly demarshalled
  and triggers a buffer over-read, a related issue to CVE-2010-0407
  (CVE-2009-4901).
  
  Buffer overflow in the MSGFunctionDemarshall function in winscard_svc.c
  in the PC/SC Smart Card daemon (aka PCSCD) in MUSCLE PCSC-Lite 1.5.4
  and earlier might allow local users to gain privileges via crafted
  SCARD_CONTROL message data, which is improperly demarshalled.  NOTE:
  this vulnerability exists because of an incorrect fix for CVE-2010-0407
  (CVE-2009-4902).
  
  Multiple buffer overflows in the MSGFunctionDemarshall function in
  winscard_svc.c in the PC/SC Smart Card daemon (aka PCSCD) in MUSCLE
  PCSC-Lite before 1.5.4 allow local users to gain privileges via
  crafted message data, which is improperly demarshalled (CVE-2010-0407).
  
  Packages for 2008.0 and 2009.0 are provided as of the Extended
  Maintenance Program. Please visit this link to learn more:
  http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=490
  
  The updated packages have been patched to correct these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "pcsc-lite on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64,
  Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2009.1,
  Mandriva Linux 2009.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-09/msg00034.php");
  script_oid("1.3.6.1.4.1.25623.1.0.313477");
  script_version("$Revision: 8485 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-01 08:16:52 +0200 (Fri, 01 Oct 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2010:189");
  script_cve_id("CVE-2010-0407", "CVE-2009-4901", "CVE-2009-4902");
  script_name("Mandriva Update for pcsc-lite MDVSA-2010:189 (pcsc-lite)");

  script_tag(name: "summary" , value: "Check for the Version of pcsc-lite");
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

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"libpcsclite1", rpm:"libpcsclite1~1.4.4~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpcsclite-devel", rpm:"libpcsclite-devel~1.4.4~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpcsclite-static-devel", rpm:"libpcsclite-static-devel~1.4.4~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcsc-lite", rpm:"pcsc-lite~1.4.4~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pcsclite1", rpm:"lib64pcsclite1~1.4.4~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pcsclite-devel", rpm:"lib64pcsclite-devel~1.4.4~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pcsclite-static-devel", rpm:"lib64pcsclite-static-devel~1.4.4~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"libpcsclite1", rpm:"libpcsclite1~1.4.102~1.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpcsclite-devel", rpm:"libpcsclite-devel~1.4.102~1.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpcsclite-static-devel", rpm:"libpcsclite-static-devel~1.4.102~1.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcsc-lite", rpm:"pcsc-lite~1.4.102~1.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pcsclite1", rpm:"lib64pcsclite1~1.4.102~1.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pcsclite-devel", rpm:"lib64pcsclite-devel~1.4.102~1.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pcsclite-static-devel", rpm:"lib64pcsclite-static-devel~1.4.102~1.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.1")
{

  if ((res = isrpmvuln(pkg:"libpcsclite1", rpm:"libpcsclite1~1.5.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpcsclite-devel", rpm:"libpcsclite-devel~1.5.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpcsclite-static-devel", rpm:"libpcsclite-static-devel~1.5.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcsc-lite", rpm:"pcsc-lite~1.5.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pcsclite1", rpm:"lib64pcsclite1~1.5.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pcsclite-devel", rpm:"lib64pcsclite-devel~1.5.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pcsclite-static-devel", rpm:"lib64pcsclite-static-devel~1.5.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"libpcsclite1", rpm:"libpcsclite1~1.4.102~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpcsclite-devel", rpm:"libpcsclite-devel~1.4.102~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpcsclite-static-devel", rpm:"libpcsclite-static-devel~1.4.102~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcsc-lite", rpm:"pcsc-lite~1.4.102~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pcsclite1", rpm:"lib64pcsclite1~1.4.102~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pcsclite-devel", rpm:"lib64pcsclite-devel~1.4.102~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64pcsclite-static-devel", rpm:"lib64pcsclite-static-devel~1.4.102~1.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
