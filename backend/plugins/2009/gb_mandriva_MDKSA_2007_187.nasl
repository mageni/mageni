###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for php MDKSA-2007:187 (php)
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
tag_insight = "Numerous vulnerabilities were discovered in the PHP scripting language
  that are corrected with this update.

  An integer overflow in the substr_compare() function allows
  context-dependent attackers to read sensitive memory via a large
  value in the length argument.  This only affects PHP5 (CVE-2007-1375).
  
  A stack-based buffer overflow in the zip:// URI wrapper in PECL
  ZIP 1.8.3 and earlier allowes remote attackers to execute arbitrary
  code via a long zip:// URL.  This only affects Corporate Server 4.0
  (CVE-2007-1399).
  
  A CRLF injection vulnerability in the FILTER_VALIDATE_EMAIL filter
  could allow an attacker to inject arbitrary email headers via a
  special email address.  This only affects Mandriva Linux 2007.1
  (CVE-2007-1900).
  
  The mcrypt_create_iv() function calls php_rand_r() with an
  uninitialized seed variable, thus always generating the same
  initialization vector, which may allow an attacker to decrypt
  certain data more easily because of the guessable encryption keys
  (CVE-2007-2727).
  
  The soap extension calls php_rand_r() with an uninitialized seec
  variable, which has unknown impact and attack vectors; an issue
  similar to that affecting mcrypt_create_iv().  This only affects PHP5
  (CVE-2007-2728).
  
  The substr_count() function allows attackers to obtain sensitive
  information via unspecified vectors.  This only affects PHP5
  (CVE-2007-2748).
  
  An infinite loop was found in the gd extension that could be used to
  cause a denial of service if a script were forced to process certain
  PNG images from untrusted sources (CVE-2007-2756).
  
  An integer overflow flaw was found in the chunk_split() function that
  ould possibly execute arbitrary code as the apache user if a remote
  attacker was able to pass arbitrary data to the third argument of
  chunk_split() (CVE-2007-2872).
  
  A flaw in the PHP session cookie handling could allow an attacker to
  create a cross-site cookie insertion attack if a victim followed an
  untrusted carefully-crafted URL (CVE-2007-3799).
  
  Various integer overflow flaws were discovered in the PHP gd extension
  that could allow a remote attacker to execute arbitrary code as the
  apache user (CVE-2007-3996).
  
  A flaw in the wordwrap() frunction could result in a denial of ervice
  if a remote attacker was able to pass arbitrary data to the function
  (CVE-2007-3998).
  
  A flaw in the money_format() function could result in an information
  leak or denial of service if a remote attacker was able to pass
  ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "php on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64,
  Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-09/msg00018.php");
  script_oid("1.3.6.1.4.1.25623.1.0.311417");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:57:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDKSA", value: "2007:187");
  script_cve_id("CVE-2007-1375", "CVE-2007-1399", "CVE-2007-1900", "CVE-2007-2727", "CVE-2007-2728", "CVE-2007-2748", "CVE-2007-2756", "CVE-2007-2872", "CVE-2007-3799", "CVE-2007-3996", "CVE-2007-3998", "CVE-2007-4658", "CVE-2007-4670");
  script_name( "Mandriva Update for php MDKSA-2007:187 (php)");

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

  if ((res = isrpmvuln(pkg:"libphp5_common5", rpm:"libphp5_common5~5.2.1~4.3mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-cgi", rpm:"php-cgi~5.2.1~4.3mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~5.2.1~4.3mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~5.2.1~4.3mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-fcgi", rpm:"php-fcgi~5.2.1~4.3mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~5.2.1~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mcrypt", rpm:"php-mcrypt~5.2.1~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-openssl", rpm:"php-openssl~5.2.1~4.3mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~5.2.1~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-zlib", rpm:"php-zlib~5.2.1~4.3mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php", rpm:"php~5.2.1~4.3mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64php5_common5", rpm:"lib64php5_common5~5.2.1~4.3mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"libphp5_common5", rpm:"libphp5_common5~5.1.6~1.9mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-cgi", rpm:"php-cgi~5.1.6~1.9mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~5.1.6~1.9mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~5.1.6~1.9mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-fcgi", rpm:"php-fcgi~5.1.6~1.9mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~5.1.6~1.3mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mcrypt", rpm:"php-mcrypt~5.1.6~1.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~5.1.6~1.2mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php", rpm:"php~5.1.6~1.9mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64php5_common5", rpm:"lib64php5_common5~5.1.6~1.9mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
