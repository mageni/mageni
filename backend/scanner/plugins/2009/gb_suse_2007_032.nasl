###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_032.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for php4,php5 SUSE-SA:2007:032
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
tag_insight = "Numerous numerous vulnerabilities have been fixed in PHP.

  Most of them were made public during the &quot;Month of PHP Bugs&quot; project
  by Stefan Esser and we thank Stefan for his reports.

  The vulnerabilities potentially lead to crashes, information leaks
  or even execution of malicious code.

  A lot of them are fixed in the last PHP security releases, 5.2.2
  and 4.4.7.

  CVE-2007-0988 / MOPB-05-2007: A unserialize problem in the zend_hash_init
  function could be used for a denial of service attack.

  CVE-2007-1001: Multiple integer overflows in the GD library embedded
  in PHP could potentially be used to execute code via crafted Wireless
  Bitmap images.

  CVE-2007-1375 / MOPB-14-2007: An integer overflow in the substr_compare
  function allows context-dependend attackers to read out memory of
  the PHP interpreter.

  CVE-2007-1376 / MOPB-15-2007: The shmop function does not validate
  its arguments, allowing context-dependend attackers to read and write
  arbitrary memory locations.

  CVE-2007-1380 / MOPB-10-2007: The php_binary serialization handler
  in the session extension allows context-dependend attackers to obtain
  sensitive information via a buffer over-read.

  CVE-2007-1383 / MOPB-01-2007: An integer overflow in the 16 Bit
  reference counter in PHP4 allows context-dependend attackers to
  execute arbitrary code by causing a value to be destroyed twice.

  CVE-2007-1453 / MOPB-19-2007: A buffer underflow in the
  PHP_FILTER_TRIM_DEFAULT macro in the ext/filter extension allows
  context-dependend attackers to potentially execute arbitrary code.

  CVE-2007-1454 / MOPB-18-2007: The ext/filter extension in PHP when
  used with the FILTER_FLAG_STRIP_LOW flag does not properly strip HTML
  tags, allowing cross site scripting.

  CVE-2007-1460 / MOPB-20-2007: The zip:// URL wrapper provided by
  the PECL zip extension did not implement safemode or open_basedir
  checks, allowing attackers to read ZIP files outside of the intended
  directories.

  CVE-2007-1461 / MOPB-21-2007: The bzip2:// URL wrapper did not
  implement safemode or open_basedir checks, allowing attackers to read
  BZIP2 archives outside of the intended directories.

  CVE-2007-1484 / MOPB-24-2007: The array_user_key_compare function
  makes erroneous calls to zval_dt ... 

  Description truncated, for more information please check the Reference URL";

tag_impact = "remote code execution";
tag_affected = "php4,php5 on SUSE LINUX 10.1, openSUSE 10.2, SuSE Linux Enterprise Server 8, SUSE SLES 9, Open Enterprise Server, Novell Linux POS 9, SUSE SLES 10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.308675");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-0988", "CVE-2007-1001", "CVE-2007-1375", "CVE-2007-1376", "CVE-2007-1380", "CVE-2007-1383", "CVE-2007-1453", "CVE-2007-1454", "CVE-2007-1460", "CVE-2007-1461", "CVE-2007-1484", "CVE-2007-1521", "CVE-2007-1522", "CVE-2007-1583", "CVE-2007-1700", "CVE-2007-1717", "CVE-2007-1718", "CVE-2007-1824", "CVE-2007-1889", "CVE-2007-1900");
  script_name( "SuSE Update for php4,php5 SUSE-SA:2007:032");

  script_tag(name:"summary", value:"Check for the Version of php4,php5");
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

if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"apache2-mod_php5", rpm:"apache2-mod_php5~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5", rpm:"php5~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-bcmath", rpm:"php5-bcmath~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-bz2", rpm:"php5-bz2~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-calendar", rpm:"php5-calendar~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ctype", rpm:"php5-ctype~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-curl", rpm:"php5-curl~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dba", rpm:"php5-dba~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dbase", rpm:"php5-dbase~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-devel", rpm:"php5-devel~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dom", rpm:"php5-dom~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-exif", rpm:"php5-exif~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-fastcgi", rpm:"php5-fastcgi~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ftp", rpm:"php5-ftp~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gd", rpm:"php5-gd~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gettext", rpm:"php5-gettext~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gmp", rpm:"php5-gmp~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-hash", rpm:"php5-hash~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-iconv", rpm:"php5-iconv~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-imap", rpm:"php5-imap~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-json", rpm:"php5-json~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ldap", rpm:"php5-ldap~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mbstring", rpm:"php5-mbstring~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mcrypt", rpm:"php5-mcrypt~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mhash", rpm:"php5-mhash~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mysql", rpm:"php5-mysql~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ncurses", rpm:"php5-ncurses~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-odbc", rpm:"php5-odbc~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-openssl", rpm:"php5-openssl~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pcntl", rpm:"php5-pcntl~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pdo", rpm:"php5-pdo~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pear", rpm:"php5-pear~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pgsql", rpm:"php5-pgsql~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-posix", rpm:"php5-posix~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pspell", rpm:"php5-pspell~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-shmop", rpm:"php5-shmop~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-snmp", rpm:"php5-snmp~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-soap", rpm:"php5-soap~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sockets", rpm:"php5-sockets~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sqlite", rpm:"php5-sqlite~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-suhosin", rpm:"php5-suhosin~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvmsg", rpm:"php5-sysvmsg~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvsem", rpm:"php5-sysvsem~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvshm", rpm:"php5-sysvshm~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-tidy", rpm:"php5-tidy~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-tokenizer", rpm:"php5-tokenizer~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-wddx", rpm:"php5-wddx~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlreader", rpm:"php5-xmlreader~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlrpc", rpm:"php5-xmlrpc~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlwriter", rpm:"php5-xmlwriter~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xsl", rpm:"php5-xsl~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-zip", rpm:"php5-zip~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-zlib", rpm:"php5-zlib~5.2.0~14", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES10")
{

  if ((res = isrpmvuln(pkg:"apache2-mod_php5", rpm:"apache2-mod_php5~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5", rpm:"php5~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-bcmath", rpm:"php5-bcmath~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-bz2", rpm:"php5-bz2~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-calendar", rpm:"php5-calendar~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ctype", rpm:"php5-ctype~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-curl", rpm:"php5-curl~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dba", rpm:"php5-dba~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dbase", rpm:"php5-dbase~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-devel", rpm:"php5-devel~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dom", rpm:"php5-dom~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-exif", rpm:"php5-exif~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-fastcgi", rpm:"php5-fastcgi~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-filepro", rpm:"php5-filepro~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ftp", rpm:"php5-ftp~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gd", rpm:"php5-gd~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gettext", rpm:"php5-gettext~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gmp", rpm:"php5-gmp~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-iconv", rpm:"php5-iconv~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-imap", rpm:"php5-imap~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ldap", rpm:"php5-ldap~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mbstring", rpm:"php5-mbstring~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mcrypt", rpm:"php5-mcrypt~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mhash", rpm:"php5-mhash~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mysql", rpm:"php5-mysql~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ncurses", rpm:"php5-ncurses~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-odbc", rpm:"php5-odbc~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-openssl", rpm:"php5-openssl~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pear", rpm:"php5-pear~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pgsql", rpm:"php5-pgsql~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-shmop", rpm:"php5-shmop~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-snmp", rpm:"php5-snmp~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sockets", rpm:"php5-sockets~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvsem", rpm:"php5-sysvsem~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvshm", rpm:"php5-sysvshm~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-tidy", rpm:"php5-tidy~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-wddx", rpm:"php5-wddx~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xsl", rpm:"php5-xsl~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-zlib", rpm:"php5-zlib~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mysqli", rpm:"php5-mysqli~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pcntl", rpm:"php5-pcntl~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pdo", rpm:"php5-pdo~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-posix", rpm:"php5-posix~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pspell", rpm:"php5-pspell~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-soap", rpm:"php5-soap~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sqlite", rpm:"php5-sqlite~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvmsg", rpm:"php5-sysvmsg~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-tokenizer", rpm:"php5-tokenizer~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlreader", rpm:"php5-xmlreader~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlrpc", rpm:"php5-xmlrpc~5.1.2~29.25.6", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESSr8")
{

  if ((res = isrpmvuln(pkg:"mod_php4", rpm:"mod_php4~4.2.2~526", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-core", rpm:"mod_php4-core~4.2.2~526", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-devel", rpm:"mod_php4-devel~4.2.2~526", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-servlet", rpm:"mod_php4-servlet~4.2.2~526", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLPOS9")
{

  if ((res = isrpmvuln(pkg:"apache-mod_php4", rpm:"apache-mod_php4~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-mod_php4", rpm:"apache2-mod_php4~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4", rpm:"mod_php4~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-apache2", rpm:"mod_php4-apache2~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-core", rpm:"mod_php4-core~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-servlet", rpm:"mod_php4-servlet~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4", rpm:"php4~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-bcmath", rpm:"php4-bcmath~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-bz2", rpm:"php4-bz2~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-calendar", rpm:"php4-calendar~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ctype", rpm:"php4-ctype~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-curl", rpm:"php4-curl~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-dba", rpm:"php4-dba~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-dbase", rpm:"php4-dbase~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-devel", rpm:"php4-devel~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-domxml", rpm:"php4-domxml~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-exif", rpm:"php4-exif~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-fastcgi", rpm:"php4-fastcgi~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-filepro", rpm:"php4-filepro~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ftp", rpm:"php4-ftp~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gd", rpm:"php4-gd~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gettext", rpm:"php4-gettext~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gmp", rpm:"php4-gmp~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-iconv", rpm:"php4-iconv~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-imap", rpm:"php4-imap~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ldap", rpm:"php4-ldap~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mbstring", rpm:"php4-mbstring~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mcal", rpm:"php4-mcal~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mcrypt", rpm:"php4-mcrypt~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mhash", rpm:"php4-mhash~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mime_magic", rpm:"php4-mime_magic~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mysql", rpm:"php4-mysql~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-pear", rpm:"php4-pear~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-pgsql", rpm:"php4-pgsql~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-qtdom", rpm:"php4-qtdom~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-readline", rpm:"php4-readline~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-recode", rpm:"php4-recode~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-servlet", rpm:"php4-servlet~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-session", rpm:"php4-session~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-shmop", rpm:"php4-shmop~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-snmp", rpm:"php4-snmp~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sockets", rpm:"php4-sockets~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-swf", rpm:"php4-swf~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sysvsem", rpm:"php4-sysvsem~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sysvshm", rpm:"php4-sysvshm~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-unixODBC", rpm:"php4-unixODBC~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-wddx", rpm:"php4-wddx~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-xslt", rpm:"php4-xslt~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-yp", rpm:"php4-yp~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-zlib", rpm:"php4-zlib~4.3.4~43.77", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"apache-mod_php4", rpm:"apache-mod_php4~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-mod_php4", rpm:"apache2-mod_php4~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4", rpm:"mod_php4~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-apache2", rpm:"mod_php4-apache2~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-core", rpm:"mod_php4-core~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-servlet", rpm:"mod_php4-servlet~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4", rpm:"php4~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-bcmath", rpm:"php4-bcmath~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-bz2", rpm:"php4-bz2~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-calendar", rpm:"php4-calendar~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ctype", rpm:"php4-ctype~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-curl", rpm:"php4-curl~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-dba", rpm:"php4-dba~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-dbase", rpm:"php4-dbase~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-devel", rpm:"php4-devel~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-domxml", rpm:"php4-domxml~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-exif", rpm:"php4-exif~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-fastcgi", rpm:"php4-fastcgi~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-filepro", rpm:"php4-filepro~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ftp", rpm:"php4-ftp~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gd", rpm:"php4-gd~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gettext", rpm:"php4-gettext~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gmp", rpm:"php4-gmp~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-iconv", rpm:"php4-iconv~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-imap", rpm:"php4-imap~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ldap", rpm:"php4-ldap~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mbstring", rpm:"php4-mbstring~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mcal", rpm:"php4-mcal~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mcrypt", rpm:"php4-mcrypt~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mhash", rpm:"php4-mhash~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mime_magic", rpm:"php4-mime_magic~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mysql", rpm:"php4-mysql~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-pear", rpm:"php4-pear~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-pgsql", rpm:"php4-pgsql~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-qtdom", rpm:"php4-qtdom~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-readline", rpm:"php4-readline~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-recode", rpm:"php4-recode~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-servlet", rpm:"php4-servlet~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-session", rpm:"php4-session~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-shmop", rpm:"php4-shmop~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-snmp", rpm:"php4-snmp~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sockets", rpm:"php4-sockets~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-swf", rpm:"php4-swf~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sysvsem", rpm:"php4-sysvsem~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sysvshm", rpm:"php4-sysvshm~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-unixODBC", rpm:"php4-unixODBC~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-wddx", rpm:"php4-wddx~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-xslt", rpm:"php4-xslt~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-yp", rpm:"php4-yp~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-zlib", rpm:"php4-zlib~4.3.4~43.77", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES9")
{

  if ((res = isrpmvuln(pkg:"apache-mod_php4", rpm:"apache-mod_php4~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-mod_php4", rpm:"apache2-mod_php4~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4", rpm:"mod_php4~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-apache2", rpm:"mod_php4-apache2~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-core", rpm:"mod_php4-core~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-servlet", rpm:"mod_php4-servlet~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4", rpm:"php4~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-bcmath", rpm:"php4-bcmath~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-bz2", rpm:"php4-bz2~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-calendar", rpm:"php4-calendar~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ctype", rpm:"php4-ctype~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-curl", rpm:"php4-curl~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-dba", rpm:"php4-dba~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-dbase", rpm:"php4-dbase~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-devel", rpm:"php4-devel~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-domxml", rpm:"php4-domxml~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-exif", rpm:"php4-exif~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-fastcgi", rpm:"php4-fastcgi~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-filepro", rpm:"php4-filepro~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ftp", rpm:"php4-ftp~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gd", rpm:"php4-gd~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gettext", rpm:"php4-gettext~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gmp", rpm:"php4-gmp~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-iconv", rpm:"php4-iconv~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-imap", rpm:"php4-imap~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ldap", rpm:"php4-ldap~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mbstring", rpm:"php4-mbstring~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mcal", rpm:"php4-mcal~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mcrypt", rpm:"php4-mcrypt~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mhash", rpm:"php4-mhash~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mime_magic", rpm:"php4-mime_magic~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mysql", rpm:"php4-mysql~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-pear", rpm:"php4-pear~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-pgsql", rpm:"php4-pgsql~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-qtdom", rpm:"php4-qtdom~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-readline", rpm:"php4-readline~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-recode", rpm:"php4-recode~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-servlet", rpm:"php4-servlet~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-session", rpm:"php4-session~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-shmop", rpm:"php4-shmop~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-snmp", rpm:"php4-snmp~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sockets", rpm:"php4-sockets~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-swf", rpm:"php4-swf~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sysvsem", rpm:"php4-sysvsem~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sysvshm", rpm:"php4-sysvshm~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-unixODBC", rpm:"php4-unixODBC~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-wddx", rpm:"php4-wddx~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-xslt", rpm:"php4-xslt~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-yp", rpm:"php4-yp~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-zlib", rpm:"php4-zlib~4.3.4~43.77", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"apache2-mod_php5", rpm:"apache2-mod_php5~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5", rpm:"php5~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-bcmath", rpm:"php5-bcmath~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-bz2", rpm:"php5-bz2~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-calendar", rpm:"php5-calendar~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ctype", rpm:"php5-ctype~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-curl", rpm:"php5-curl~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dba", rpm:"php5-dba~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dbase", rpm:"php5-dbase~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-devel", rpm:"php5-devel~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dom", rpm:"php5-dom~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-exif", rpm:"php5-exif~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-fastcgi", rpm:"php5-fastcgi~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-filepro", rpm:"php5-filepro~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ftp", rpm:"php5-ftp~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gd", rpm:"php5-gd~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gettext", rpm:"php5-gettext~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gmp", rpm:"php5-gmp~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-iconv", rpm:"php5-iconv~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-imap", rpm:"php5-imap~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ldap", rpm:"php5-ldap~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mbstring", rpm:"php5-mbstring~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mcrypt", rpm:"php5-mcrypt~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mhash", rpm:"php5-mhash~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mysql", rpm:"php5-mysql~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mysqli", rpm:"php5-mysqli~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ncurses", rpm:"php5-ncurses~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-odbc", rpm:"php5-odbc~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-openssl", rpm:"php5-openssl~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pcntl", rpm:"php5-pcntl~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pdo", rpm:"php5-pdo~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pdo_mysql", rpm:"php5-pdo_mysql~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pdo_pgsql", rpm:"php5-pdo_pgsql~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pdo_sqlite", rpm:"php5-pdo_sqlite~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pear", rpm:"php5-pear~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pgsql", rpm:"php5-pgsql~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-posix", rpm:"php5-posix~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pspell", rpm:"php5-pspell~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-shmop", rpm:"php5-shmop~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-snmp", rpm:"php5-snmp~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-soap", rpm:"php5-soap~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sockets", rpm:"php5-sockets~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sqlite", rpm:"php5-sqlite~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvmsg", rpm:"php5-sysvmsg~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvsem", rpm:"php5-sysvsem~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvshm", rpm:"php5-sysvshm~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-tidy", rpm:"php5-tidy~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-tokenizer", rpm:"php5-tokenizer~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-wddx", rpm:"php5-wddx~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlreader", rpm:"php5-xmlreader~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlrpc", rpm:"php5-xmlrpc~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlwriter", rpm:"php5-xmlwriter~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xsl", rpm:"php5-xsl~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-zlib", rpm:"php5-zlib~5.1.2~29.25.6", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
