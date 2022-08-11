###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for cups MDVSA-2010:073-1 (cups)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in cups:

  CUPS in does not properly handle (1) HTTP headers and (2) HTML
  templates, which allows remote attackers to conduct cross-site
  scripting (XSS) attacks and HTTP response splitting attacks via vectors
  related to (a) the product's web interface, (b) the configuration of
  the print system, and (c) the titles of printed jobs (CVE-2009-2820).
  
  Use-after-free vulnerability in the abstract file-descriptor handling
  interface in the cupsdDoSelect function in scheduler/select.c in the
  scheduler in cupsd in CUPS 1.3.7 and 1.3.10 allows remote attackers
  to cause a denial of service (daemon crash or hang) via a client
  disconnection during listing of a large number of print jobs, related
  to improperly maintaining a reference count.  NOTE: some of these
  details are obtained from third party information (CVE-2009-3553).
  
  Use-after-free vulnerability in the abstract file-descriptor handling
  interface in the cupsdDoSelect function in scheduler/select.c in the
  scheduler in cupsd in CUPS 1.3.7, 1.3.9, 1.3.10, and 1.4.1, when kqueue
  or epoll is used, allows remote attackers to cause a denial of service
  (daemon crash or hang) via a client disconnection during listing
  of a large number of print jobs, related to improperly maintaining
  a reference count.  NOTE: some of these details are obtained from
  third party information.  NOTE: this vulnerability exists because of
  an incomplete fix for CVE-2009-3553 (CVE-2010-0302).
  
  The _cupsGetlang function, as used by lppasswd.c in lppasswd in CUPS
  1.2.2, 1.3.7, 1.3.9, and 1.4.1, relies on an environment variable
  to determine the file that provides localized message strings, which
  allows local users to gain privileges via a file that contains crafted
  localization data with format string specifiers (CVE-2010-0393).
  
  The updated packages have been patched to correct these issues.
  
  Update:
  
  Packages for Mandriva Linux 2010.0 was missing with
  MDVSA-2010:073. This advisory provides packages for 2010.0 as well.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "cups on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-04/msg00014.php");
  script_oid("1.3.6.1.4.1.25623.1.0.312822");
  script_version("$Revision: 8274 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-16 17:02:11 +0200 (Fri, 16 Apr 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2010:073-1");
  script_cve_id("CVE-2009-2820", "CVE-2009-3553", "CVE-2010-0302", "CVE-2010-0393");
  script_name("Mandriva Update for cups MDVSA-2010:073-1 (cups)");

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

if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.4.1~12.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-common", rpm:"cups-common~1.4.1~12.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-serial", rpm:"cups-serial~1.4.1~12.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~1.4.1~12.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcups2-devel", rpm:"libcups2-devel~1.4.1~12.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-cups", rpm:"php-cups~1.4.1~12.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64cups2", rpm:"lib64cups2~1.4.1~12.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64cups2-devel", rpm:"lib64cups2-devel~1.4.1~12.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
