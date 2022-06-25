###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for php53 CESA-2011:1423 centos5 x86_64
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-November/018146.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881333");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:25:50 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-0708", "CVE-2011-1148", "CVE-2011-1466", "CVE-2011-1468",
                "CVE-2011-1469", "CVE-2011-1471", "CVE-2011-1938", "CVE-2011-2202",
                "CVE-2011-2483");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for php53 CESA-2011:1423 centos5 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php53'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"php53 on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Server.

  A signedness issue was found in the way the PHP crypt() function handled
  8-bit characters in passwords when using Blowfish hashing. Up to three
  characters immediately preceding a non-ASCII character (one with the high
  bit set) had no effect on the hash result, thus shortening the effective
  password length. This made brute-force guessing more efficient as several
  different passwords were hashed to the same value. (CVE-2011-2483)

  Note: Due to the CVE-2011-2483 fix, after installing this update some users
  may not be able to log in to PHP applications that hash passwords with
  Blowfish using the PHP crypt() function. Refer to the upstream
  'CRYPT_BLOWFISH security fix details' document, linked to in the
  References, for details.

  An insufficient input validation flaw, leading to a buffer over-read, was
  found in the PHP exif extension. A specially-crafted image file could cause
  the PHP interpreter to crash when a PHP script tries to extract
  Exchangeable image file format (Exif) metadata from the image file.
  (CVE-2011-0708)

  An integer overflow flaw was found in the PHP calendar extension. A remote
  attacker able to make a PHP script call SdnToJulian() with a large value
  could cause the PHP interpreter to crash. (CVE-2011-1466)

  Multiple memory leak flaws were found in the PHP OpenSSL extension. A
  remote attacker able to make a PHP script use openssl_encrypt() or
  openssl_decrypt() repeatedly could cause the PHP interpreter to use an
  excessive amount of memory. (CVE-2011-1468)

  A use-after-free flaw was found in the PHP substr_replace() function. If a
  PHP script used the same variable as multiple function arguments, a remote
  attacker could possibly use this to crash the PHP interpreter or, possibly,
  execute arbitrary code. (CVE-2011-1148)

  A bug in the PHP Streams component caused the PHP interpreter to crash if
  an FTP wrapper connection was made through an HTTP proxy. A remote attacker
  could possibly trigger this issue if a PHP script accepted an untrusted URL
  to connect to. (CVE-2011-1469)

  An integer signedness issue was found in the PHP zip extension. An attacker
  could use a specially-crafted ZIP archive to cause the PHP interpreter to
  use an excessive amount of CPU time until the script execution time limit
  is reached. (CVE-2011-1471)

  A stack-based buffer overflow flaw was found in the way the PHP socket
  extension handled long AF_UNIX socket addresses. An attacker able to make a
  PHP script connect to a long AF_ ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"php53", rpm:"php53~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-bcmath", rpm:"php53-bcmath~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-cli", rpm:"php53-cli~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-common", rpm:"php53-common~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-dba", rpm:"php53-dba~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-devel", rpm:"php53-devel~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-gd", rpm:"php53-gd~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-imap", rpm:"php53-imap~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-intl", rpm:"php53-intl~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-ldap", rpm:"php53-ldap~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-mbstring", rpm:"php53-mbstring~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-mysql", rpm:"php53-mysql~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-odbc", rpm:"php53-odbc~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-pdo", rpm:"php53-pdo~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-pgsql", rpm:"php53-pgsql~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-process", rpm:"php53-process~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-pspell", rpm:"php53-pspell~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-snmp", rpm:"php53-snmp~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-soap", rpm:"php53-soap~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-xml", rpm:"php53-xml~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-xmlrpc", rpm:"php53-xmlrpc~5.3.3~1.el5_7.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
