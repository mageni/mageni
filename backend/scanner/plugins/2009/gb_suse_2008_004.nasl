###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2008_004.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for php4, php5 SUSE-SA:2008:004
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
tag_insight = "php5 was updated to version 5.2.5 to fix several security
  vulnerabilities. For php4 on SLES9 the patches were backported.

  - php4 on SLES9 and php5 on SLES10/10.1 contained a copy of the pcre
  library which was vulnerable to several security issues. On SLES9
  the included library was patched. SLES10/10.1 now uses the system
  pcre library. 10.2 and 10.3 already used the system pcre library
  before.
  CVE-2006-7227
  CVE-2006-7228

  - flaws in processing multi byte sequences in htmlentities/htmlspecialchars
  CVE-2007-5898

  - overly long arguments to the dl() function could crash php
  CVE-2007-4825

  - overy long arguments to the glob() function could crash php
  CVE-2007-4782

  - overly long arguments to some iconv functions could crash php
  CVE-2007-4840

  - overy long arguments to the setlocale() function could crash php
  CVE-2007-4784

  - the wordwrap-function could cause a floating point exception
  CVE-2007-3998

  - overy long arguments to the fnmatch() function could crash php
  CVE-2007-4782

  - incorrect size calculation in the chunk_split function could lead
  to a buffer overflow
  CVE-2007-4661

  - flaws in the GD extension could lead to integer overflows
  CVE-2007-3996

  - the money_format function contained format string flaws
  CVE-2007-4658";

tag_impact = "remote code execution";
tag_affected = "php4, php5 on SUSE LINUX 10.1, openSUSE 10.2, openSUSE 10.3, SUSE SLES 9, Novell Linux Desktop 9 SDK, Open Enterprise Server, Novell Linux POS 9, SLE SDK 10 SP1, SUSE Linux Enterprise Server 10 SP1";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.309324");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-4872", "CVE-2006-7224", "CVE-2006-7225", "CVE-2006-7226", "CVE-2006-7227", "CVE-2006-7228", "CVE-2006-7230", "CVE-2007-1659", "CVE-2007-1660", "CVE-2007-2872", "CVE-2007-3996", "CVE-2007-3998", "CVE-2007-4658", "CVE-2007-4661", "CVE-2007-4782", "CVE-2007-4784", "CVE-2007-4825", "CVE-2007-4840", "CVE-2007-5898");
  script_name( "SuSE Update for php4, php5 SUSE-SA:2008:004");

  script_tag(name:"summary", value:"Check for the Version of php4, php5");
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

  if ((res = isrpmvuln(pkg:"apache2-mod_php5", rpm:"apache2-mod_php5~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5", rpm:"php5~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-bcmath", rpm:"php5-bcmath~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-bz2", rpm:"php5-bz2~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-calendar", rpm:"php5-calendar~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ctype", rpm:"php5-ctype~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-curl", rpm:"php5-curl~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dba", rpm:"php5-dba~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dbase", rpm:"php5-dbase~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-devel", rpm:"php5-devel~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dom", rpm:"php5-dom~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-exif", rpm:"php5-exif~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-fastcgi", rpm:"php5-fastcgi~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ftp", rpm:"php5-ftp~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gd", rpm:"php5-gd~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gettext", rpm:"php5-gettext~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gmp", rpm:"php5-gmp~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-hash", rpm:"php5-hash~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-iconv", rpm:"php5-iconv~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-imap", rpm:"php5-imap~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-json", rpm:"php5-json~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ldap", rpm:"php5-ldap~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mbstring", rpm:"php5-mbstring~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mcrypt", rpm:"php5-mcrypt~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mhash", rpm:"php5-mhash~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mysql", rpm:"php5-mysql~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ncurses", rpm:"php5-ncurses~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-odbc", rpm:"php5-odbc~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-openssl", rpm:"php5-openssl~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pcntl", rpm:"php5-pcntl~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pdo", rpm:"php5-pdo~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pear", rpm:"php5-pear~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pgsql", rpm:"php5-pgsql~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-posix", rpm:"php5-posix~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pspell", rpm:"php5-pspell~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-readline", rpm:"php5-readline~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-shmop", rpm:"php5-shmop~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-snmp", rpm:"php5-snmp~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-soap", rpm:"php5-soap~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sockets", rpm:"php5-sockets~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sqlite", rpm:"php5-sqlite~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-suhosin", rpm:"php5-suhosin~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvmsg", rpm:"php5-sysvmsg~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvsem", rpm:"php5-sysvsem~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvshm", rpm:"php5-sysvshm~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-tidy", rpm:"php5-tidy~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-tokenizer", rpm:"php5-tokenizer~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-wddx", rpm:"php5-wddx~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlreader", rpm:"php5-xmlreader~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlrpc", rpm:"php5-xmlrpc~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlwriter", rpm:"php5-xmlwriter~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xsl", rpm:"php5-xsl~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-zip", rpm:"php5-zip~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-zlib", rpm:"php5-zlib~5.2.5~8.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"apache2-mod_php5", rpm:"apache2-mod_php5~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5", rpm:"php5~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-bcmath", rpm:"php5-bcmath~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-bz2", rpm:"php5-bz2~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-calendar", rpm:"php5-calendar~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ctype", rpm:"php5-ctype~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-curl", rpm:"php5-curl~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dba", rpm:"php5-dba~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dbase", rpm:"php5-dbase~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-devel", rpm:"php5-devel~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dom", rpm:"php5-dom~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-exif", rpm:"php5-exif~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-fastcgi", rpm:"php5-fastcgi~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ftp", rpm:"php5-ftp~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gd", rpm:"php5-gd~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gettext", rpm:"php5-gettext~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gmp", rpm:"php5-gmp~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-hash", rpm:"php5-hash~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-iconv", rpm:"php5-iconv~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-imap", rpm:"php5-imap~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-json", rpm:"php5-json~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ldap", rpm:"php5-ldap~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mbstring", rpm:"php5-mbstring~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mcrypt", rpm:"php5-mcrypt~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mhash", rpm:"php5-mhash~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mysql", rpm:"php5-mysql~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ncurses", rpm:"php5-ncurses~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-odbc", rpm:"php5-odbc~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-openssl", rpm:"php5-openssl~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pcntl", rpm:"php5-pcntl~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pdo", rpm:"php5-pdo~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pear", rpm:"php5-pear~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pgsql", rpm:"php5-pgsql~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-posix", rpm:"php5-posix~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pspell", rpm:"php5-pspell~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-shmop", rpm:"php5-shmop~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-snmp", rpm:"php5-snmp~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-soap", rpm:"php5-soap~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sockets", rpm:"php5-sockets~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sqlite", rpm:"php5-sqlite~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-suhosin", rpm:"php5-suhosin~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvmsg", rpm:"php5-sysvmsg~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvsem", rpm:"php5-sysvsem~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvshm", rpm:"php5-sysvshm~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-tidy", rpm:"php5-tidy~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-tokenizer", rpm:"php5-tokenizer~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-wddx", rpm:"php5-wddx~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlreader", rpm:"php5-xmlreader~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlrpc", rpm:"php5-xmlrpc~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlwriter", rpm:"php5-xmlwriter~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xsl", rpm:"php5-xsl~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-zip", rpm:"php5-zip~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-zlib", rpm:"php5-zlib~5.2.5~18.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLPOS9")
{

  if ((res = isrpmvuln(pkg:"mod_php4-core", rpm:"mod_php4-core~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4", rpm:"php4~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-bcmath", rpm:"php4-bcmath~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-bz2", rpm:"php4-bz2~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-calendar", rpm:"php4-calendar~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ctype", rpm:"php4-ctype~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-curl", rpm:"php4-curl~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-dba", rpm:"php4-dba~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-dbase", rpm:"php4-dbase~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-devel", rpm:"php4-devel~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-domxml", rpm:"php4-domxml~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-exif", rpm:"php4-exif~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-fastcgi", rpm:"php4-fastcgi~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-filepro", rpm:"php4-filepro~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ftp", rpm:"php4-ftp~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gd", rpm:"php4-gd~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gettext", rpm:"php4-gettext~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gmp", rpm:"php4-gmp~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-iconv", rpm:"php4-iconv~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-imap", rpm:"php4-imap~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ldap", rpm:"php4-ldap~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mbstring", rpm:"php4-mbstring~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mcal", rpm:"php4-mcal~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mcrypt", rpm:"php4-mcrypt~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mhash", rpm:"php4-mhash~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mime_magic", rpm:"php4-mime_magic~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mysql", rpm:"php4-mysql~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-pear", rpm:"php4-pear~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-pgsql", rpm:"php4-pgsql~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-qtdom", rpm:"php4-qtdom~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-readline", rpm:"php4-readline~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-recode", rpm:"php4-recode~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-servlet", rpm:"php4-servlet~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-session", rpm:"php4-session~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-shmop", rpm:"php4-shmop~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-snmp", rpm:"php4-snmp~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sockets", rpm:"php4-sockets~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-swf", rpm:"php4-swf~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sysvsem", rpm:"php4-sysvsem~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sysvshm", rpm:"php4-sysvshm~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-unixODBC", rpm:"php4-unixODBC~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-wddx", rpm:"php4-wddx~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-xslt", rpm:"php4-xslt~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-yp", rpm:"php4-yp~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-zlib", rpm:"php4-zlib~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_php4", rpm:"apache-mod_php4~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-mod_php4", rpm:"apache2-mod_php4~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4", rpm:"mod_php4~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-apache2", rpm:"mod_php4-apache2~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-servlet", rpm:"mod_php4-servlet~4.3.4~43.85", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"mod_php4-core", rpm:"mod_php4-core~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4", rpm:"php4~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-bcmath", rpm:"php4-bcmath~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-bz2", rpm:"php4-bz2~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-calendar", rpm:"php4-calendar~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ctype", rpm:"php4-ctype~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-curl", rpm:"php4-curl~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-dba", rpm:"php4-dba~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-dbase", rpm:"php4-dbase~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-devel", rpm:"php4-devel~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-domxml", rpm:"php4-domxml~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-exif", rpm:"php4-exif~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-fastcgi", rpm:"php4-fastcgi~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-filepro", rpm:"php4-filepro~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ftp", rpm:"php4-ftp~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gd", rpm:"php4-gd~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gettext", rpm:"php4-gettext~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gmp", rpm:"php4-gmp~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-iconv", rpm:"php4-iconv~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-imap", rpm:"php4-imap~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ldap", rpm:"php4-ldap~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mbstring", rpm:"php4-mbstring~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mcal", rpm:"php4-mcal~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mcrypt", rpm:"php4-mcrypt~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mhash", rpm:"php4-mhash~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mime_magic", rpm:"php4-mime_magic~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mysql", rpm:"php4-mysql~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-pear", rpm:"php4-pear~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-pgsql", rpm:"php4-pgsql~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-qtdom", rpm:"php4-qtdom~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-readline", rpm:"php4-readline~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-recode", rpm:"php4-recode~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-servlet", rpm:"php4-servlet~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-session", rpm:"php4-session~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-shmop", rpm:"php4-shmop~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-snmp", rpm:"php4-snmp~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sockets", rpm:"php4-sockets~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-swf", rpm:"php4-swf~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sysvsem", rpm:"php4-sysvsem~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sysvshm", rpm:"php4-sysvshm~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-unixODBC", rpm:"php4-unixODBC~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-wddx", rpm:"php4-wddx~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-xslt", rpm:"php4-xslt~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-yp", rpm:"php4-yp~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-zlib", rpm:"php4-zlib~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_php4", rpm:"apache-mod_php4~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-mod_php4", rpm:"apache2-mod_php4~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4", rpm:"mod_php4~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-apache2", rpm:"mod_php4-apache2~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-servlet", rpm:"mod_php4-servlet~4.3.4~43.85", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES9")
{

  if ((res = isrpmvuln(pkg:"mod_php4-core", rpm:"mod_php4-core~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4", rpm:"php4~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-bcmath", rpm:"php4-bcmath~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-bz2", rpm:"php4-bz2~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-calendar", rpm:"php4-calendar~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ctype", rpm:"php4-ctype~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-curl", rpm:"php4-curl~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-dba", rpm:"php4-dba~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-dbase", rpm:"php4-dbase~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-devel", rpm:"php4-devel~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-domxml", rpm:"php4-domxml~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-exif", rpm:"php4-exif~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-fastcgi", rpm:"php4-fastcgi~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-filepro", rpm:"php4-filepro~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ftp", rpm:"php4-ftp~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gd", rpm:"php4-gd~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gettext", rpm:"php4-gettext~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gmp", rpm:"php4-gmp~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-iconv", rpm:"php4-iconv~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-imap", rpm:"php4-imap~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ldap", rpm:"php4-ldap~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mbstring", rpm:"php4-mbstring~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mcal", rpm:"php4-mcal~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mcrypt", rpm:"php4-mcrypt~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mhash", rpm:"php4-mhash~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mime_magic", rpm:"php4-mime_magic~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mysql", rpm:"php4-mysql~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-pear", rpm:"php4-pear~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-pgsql", rpm:"php4-pgsql~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-qtdom", rpm:"php4-qtdom~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-readline", rpm:"php4-readline~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-recode", rpm:"php4-recode~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-servlet", rpm:"php4-servlet~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-session", rpm:"php4-session~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-shmop", rpm:"php4-shmop~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-snmp", rpm:"php4-snmp~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sockets", rpm:"php4-sockets~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-swf", rpm:"php4-swf~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sysvsem", rpm:"php4-sysvsem~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sysvshm", rpm:"php4-sysvshm~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-unixODBC", rpm:"php4-unixODBC~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-wddx", rpm:"php4-wddx~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-xslt", rpm:"php4-xslt~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-yp", rpm:"php4-yp~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-zlib", rpm:"php4-zlib~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_php4", rpm:"apache-mod_php4~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-mod_php4", rpm:"apache2-mod_php4~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4", rpm:"mod_php4~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-apache2", rpm:"mod_php4-apache2~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-servlet", rpm:"mod_php4-servlet~4.3.4~43.85", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9SDK")
{

  if ((res = isrpmvuln(pkg:"mod_php4-core", rpm:"mod_php4-core~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4", rpm:"php4~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-bcmath", rpm:"php4-bcmath~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-bz2", rpm:"php4-bz2~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-calendar", rpm:"php4-calendar~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ctype", rpm:"php4-ctype~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-curl", rpm:"php4-curl~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-dba", rpm:"php4-dba~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-dbase", rpm:"php4-dbase~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-devel", rpm:"php4-devel~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-domxml", rpm:"php4-domxml~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-exif", rpm:"php4-exif~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-fastcgi", rpm:"php4-fastcgi~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-filepro", rpm:"php4-filepro~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ftp", rpm:"php4-ftp~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gd", rpm:"php4-gd~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gettext", rpm:"php4-gettext~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-gmp", rpm:"php4-gmp~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-iconv", rpm:"php4-iconv~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-imap", rpm:"php4-imap~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-ldap", rpm:"php4-ldap~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mbstring", rpm:"php4-mbstring~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mcal", rpm:"php4-mcal~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mcrypt", rpm:"php4-mcrypt~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mhash", rpm:"php4-mhash~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mime_magic", rpm:"php4-mime_magic~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-mysql", rpm:"php4-mysql~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-pear", rpm:"php4-pear~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-pgsql", rpm:"php4-pgsql~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-qtdom", rpm:"php4-qtdom~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-readline", rpm:"php4-readline~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-recode", rpm:"php4-recode~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-servlet", rpm:"php4-servlet~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-session", rpm:"php4-session~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-shmop", rpm:"php4-shmop~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-snmp", rpm:"php4-snmp~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sockets", rpm:"php4-sockets~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-swf", rpm:"php4-swf~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sysvsem", rpm:"php4-sysvsem~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-sysvshm", rpm:"php4-sysvshm~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-unixODBC", rpm:"php4-unixODBC~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-wddx", rpm:"php4-wddx~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-xslt", rpm:"php4-xslt~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-yp", rpm:"php4-yp~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php4-zlib", rpm:"php4-zlib~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_php4", rpm:"apache-mod_php4~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-mod_php4", rpm:"apache2-mod_php4~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4", rpm:"mod_php4~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-apache2", rpm:"mod_php4-apache2~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_php4-servlet", rpm:"mod_php4-servlet~4.3.4~43.85", rls:"NLDk9SDK")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "LES10SP1")
{

  if ((res = isrpmvuln(pkg:"apache2-mod_php5", rpm:"apache2-mod_php5~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5", rpm:"php5~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-bcmath", rpm:"php5-bcmath~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-bz2", rpm:"php5-bz2~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-calendar", rpm:"php5-calendar~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ctype", rpm:"php5-ctype~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-curl", rpm:"php5-curl~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dba", rpm:"php5-dba~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dbase", rpm:"php5-dbase~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-devel", rpm:"php5-devel~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dom", rpm:"php5-dom~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-exif", rpm:"php5-exif~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-fastcgi", rpm:"php5-fastcgi~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-filepro", rpm:"php5-filepro~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ftp", rpm:"php5-ftp~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gd", rpm:"php5-gd~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gettext", rpm:"php5-gettext~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gmp", rpm:"php5-gmp~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-iconv", rpm:"php5-iconv~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-imap", rpm:"php5-imap~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ldap", rpm:"php5-ldap~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mbstring", rpm:"php5-mbstring~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mcrypt", rpm:"php5-mcrypt~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mhash", rpm:"php5-mhash~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mysql", rpm:"php5-mysql~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mysqli", rpm:"php5-mysqli~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ncurses", rpm:"php5-ncurses~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-odbc", rpm:"php5-odbc~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-openssl", rpm:"php5-openssl~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pcntl", rpm:"php5-pcntl~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pdo", rpm:"php5-pdo~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pear", rpm:"php5-pear~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pgsql", rpm:"php5-pgsql~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-posix", rpm:"php5-posix~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pspell", rpm:"php5-pspell~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-shmop", rpm:"php5-shmop~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-snmp", rpm:"php5-snmp~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-soap", rpm:"php5-soap~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sockets", rpm:"php5-sockets~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sqlite", rpm:"php5-sqlite~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvmsg", rpm:"php5-sysvmsg~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvsem", rpm:"php5-sysvsem~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvshm", rpm:"php5-sysvshm~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-tidy", rpm:"php5-tidy~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-tokenizer", rpm:"php5-tokenizer~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-wddx", rpm:"php5-wddx~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlreader", rpm:"php5-xmlreader~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlrpc", rpm:"php5-xmlrpc~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xsl", rpm:"php5-xsl~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-zlib", rpm:"php5-zlib~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-suhosin", rpm:"php5-suhosin~5.1.2~29.50", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDK10SP1")
{

  if ((res = isrpmvuln(pkg:"apache2-mod_php5", rpm:"apache2-mod_php5~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5", rpm:"php5~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-bcmath", rpm:"php5-bcmath~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-bz2", rpm:"php5-bz2~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-calendar", rpm:"php5-calendar~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ctype", rpm:"php5-ctype~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-curl", rpm:"php5-curl~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dba", rpm:"php5-dba~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dbase", rpm:"php5-dbase~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-devel", rpm:"php5-devel~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dom", rpm:"php5-dom~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-exif", rpm:"php5-exif~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-fastcgi", rpm:"php5-fastcgi~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-filepro", rpm:"php5-filepro~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ftp", rpm:"php5-ftp~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gd", rpm:"php5-gd~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gettext", rpm:"php5-gettext~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gmp", rpm:"php5-gmp~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-iconv", rpm:"php5-iconv~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-imap", rpm:"php5-imap~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ldap", rpm:"php5-ldap~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mbstring", rpm:"php5-mbstring~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mcrypt", rpm:"php5-mcrypt~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mhash", rpm:"php5-mhash~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mysql", rpm:"php5-mysql~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mysqli", rpm:"php5-mysqli~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ncurses", rpm:"php5-ncurses~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-odbc", rpm:"php5-odbc~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-openssl", rpm:"php5-openssl~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pcntl", rpm:"php5-pcntl~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pdo", rpm:"php5-pdo~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pear", rpm:"php5-pear~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pgsql", rpm:"php5-pgsql~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-posix", rpm:"php5-posix~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pspell", rpm:"php5-pspell~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-shmop", rpm:"php5-shmop~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-snmp", rpm:"php5-snmp~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-soap", rpm:"php5-soap~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sockets", rpm:"php5-sockets~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sqlite", rpm:"php5-sqlite~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvmsg", rpm:"php5-sysvmsg~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvsem", rpm:"php5-sysvsem~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvshm", rpm:"php5-sysvshm~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-tidy", rpm:"php5-tidy~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-tokenizer", rpm:"php5-tokenizer~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-wddx", rpm:"php5-wddx~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlreader", rpm:"php5-xmlreader~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlrpc", rpm:"php5-xmlrpc~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xsl", rpm:"php5-xsl~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-zlib", rpm:"php5-zlib~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-suhosin", rpm:"php5-suhosin~5.1.2~29.50", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"apache2-mod_php5", rpm:"apache2-mod_php5~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5", rpm:"php5~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-bcmath", rpm:"php5-bcmath~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-bz2", rpm:"php5-bz2~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-calendar", rpm:"php5-calendar~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ctype", rpm:"php5-ctype~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-curl", rpm:"php5-curl~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dba", rpm:"php5-dba~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dbase", rpm:"php5-dbase~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-devel", rpm:"php5-devel~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-dom", rpm:"php5-dom~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-exif", rpm:"php5-exif~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-fastcgi", rpm:"php5-fastcgi~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-filepro", rpm:"php5-filepro~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ftp", rpm:"php5-ftp~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gd", rpm:"php5-gd~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gettext", rpm:"php5-gettext~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-gmp", rpm:"php5-gmp~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-iconv", rpm:"php5-iconv~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-imap", rpm:"php5-imap~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ldap", rpm:"php5-ldap~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mbstring", rpm:"php5-mbstring~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mcrypt", rpm:"php5-mcrypt~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mhash", rpm:"php5-mhash~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mysql", rpm:"php5-mysql~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-mysqli", rpm:"php5-mysqli~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-ncurses", rpm:"php5-ncurses~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-odbc", rpm:"php5-odbc~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-openssl", rpm:"php5-openssl~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pcntl", rpm:"php5-pcntl~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pdo", rpm:"php5-pdo~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pdo_mysql", rpm:"php5-pdo_mysql~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pdo_pgsql", rpm:"php5-pdo_pgsql~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pdo_sqlite", rpm:"php5-pdo_sqlite~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pear", rpm:"php5-pear~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pgsql", rpm:"php5-pgsql~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-posix", rpm:"php5-posix~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-pspell", rpm:"php5-pspell~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-shmop", rpm:"php5-shmop~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-snmp", rpm:"php5-snmp~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-soap", rpm:"php5-soap~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sockets", rpm:"php5-sockets~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sqlite", rpm:"php5-sqlite~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvmsg", rpm:"php5-sysvmsg~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvsem", rpm:"php5-sysvsem~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-sysvshm", rpm:"php5-sysvshm~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-tidy", rpm:"php5-tidy~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-tokenizer", rpm:"php5-tokenizer~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-wddx", rpm:"php5-wddx~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlreader", rpm:"php5-xmlreader~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlrpc", rpm:"php5-xmlrpc~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xmlwriter", rpm:"php5-xmlwriter~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-xsl", rpm:"php5-xsl~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php5-zlib", rpm:"php5-zlib~5.1.2~29.50", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
