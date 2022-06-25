###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for cups MDVSA-2010:233 (cups)
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
tag_insight = "Multiple vulnerabilities were discovered and corrected in cups:

  Cross-site request forgery (CSRF) vulnerability in the web interface
  in CUPS, allows remote attackers to hijack the authentication of
  administrators for requests that change settings (CVE-2010-0540).
  
  ipp.c in cupsd in CUPS 1.4.4 and earlier does not properly allocate
  memory for attribute values with invalid string data types, which
  allows remote attackers to cause a denial of service (use-after-free
  and application crash) or possibly execute arbitrary code via a
  crafted IPP request (CVE-2010-2941).
  
  The updated packages have been patched to correct these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "cups on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-11/msg00027.php");
  script_oid("1.3.6.1.4.1.25623.1.0.312974");
  script_version("$Revision: 8228 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-11-23 15:30:07 +0100 (Tue, 23 Nov 2010)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2010:233");
  script_cve_id("CVE-2010-0540", "CVE-2010-2941");
  script_name("Mandriva Update for cups MDVSA-2010:233 (cups)");

  script_tag(name: "summary" , value: "Check for the Version of cups");
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

if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.4.3~3.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-common", rpm:"cups-common~1.4.3~3.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-serial", rpm:"cups-serial~1.4.3~3.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~1.4.3~3.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcups2-devel", rpm:"libcups2-devel~1.4.3~3.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-cups", rpm:"php-cups~1.4.3~3.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64cups2", rpm:"lib64cups2~1.4.3~3.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64cups2-devel", rpm:"lib64cups2-devel~1.4.3~3.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
