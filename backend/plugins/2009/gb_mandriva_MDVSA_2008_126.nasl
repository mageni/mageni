###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for php MDVSA-2008:126 (php)
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
tag_insight = "A number of vulnerabilities have been found and corrected in PHP:

  PHP 5.2.1 would allow context-dependent attackers to read portions
  of heap memory by executing certain scripts with a serialized data
  input string beginning with 'S:', which did not properly track the
  number of input bytes being processed (CVE-2007-1649).
  
  A vulnerability in the chunk_split() function in PHP prior to 5.2.4
  has unknown impact and attack vectors, related to an incorrect size
  calculation (CVE-2007-4660).
  
  The htmlentities() and htmlspecialchars() functions in PHP prior to
  5.2.5 accepted partial multibyte sequences, which has unknown impact
  and attack vectors (CVE-2007-5898).
  
  The output_add_rewrite_var() function in PHP prior to 5.2.5 rewrites
  local forms in which the ACTION attribute references a non-local URL,
  which could allow a remote attacker to obtain potentially sensitive
  information by reading the requests for this URL (CVE-2007-5899).
  
  The escapeshellcmd() API function in PHP prior to 5.2.6 has unknown
  impact and context-dependent attack vectors related to incomplete
  multibyte characters (CVE-2008-2051).
  
  Weaknesses in the GENERATE_SEED macro in PHP prior to 4.4.8 and 5.2.5
  were discovered that could produce a zero seed in rare circumstances on
  32bit systems and generations a portion of zero bits during conversion
  due to insufficient precision on 64bit systems (CVE-2008-2107,
  CVE-2008-2108).
  
  The IMAP module in PHP uses obsolete API calls that allow
  context-dependent attackers to cause a denial of service (crash)
  via a long IMAP request (CVE-2008-2829).
  
  The updated packages have been patched to correct these issues.";

tag_affected = "php on Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-07/msg00004.php");
  script_oid("1.3.6.1.4.1.25623.1.0.308034");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:26:37 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2008:126");
  script_cve_id("CVE-2007-1649", "CVE-2007-4660", "CVE-2007-5898", "CVE-2007-5899", "CVE-2008-2051", "CVE-2008-2107", "CVE-2008-2108", "CVE-2008-2829");
  script_name( "Mandriva Update for php MDVSA-2008:126 (php)");

  script_tag(name:"summary", value:"Check for the Version of php");
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

  if ((res = isrpmvuln(pkg:"libphp5_common5", rpm:"libphp5_common5~5.2.1~4.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-cgi", rpm:"php-cgi~5.2.1~4.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~5.2.1~4.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~5.2.1~4.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-fcgi", rpm:"php-fcgi~5.2.1~4.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-imap", rpm:"php-imap~5.2.1~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-openssl", rpm:"php-openssl~5.2.1~4.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-zlib", rpm:"php-zlib~5.2.1~4.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php", rpm:"php~5.2.1~4.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64php5_common5", rpm:"lib64php5_common5~5.2.1~4.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
