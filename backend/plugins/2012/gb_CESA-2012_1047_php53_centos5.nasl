###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for php53 CESA-2012:1047 centos5
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-June/018703.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881144");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:21:42 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2010-2950", "CVE-2011-4153", "CVE-2012-0057", "CVE-2012-0789",
                "CVE-2012-1172", "CVE-2012-2143", "CVE-2012-2336", "CVE-2012-2386",
                "CVE-2012-1823");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for php53 CESA-2012:1047 centos5");

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

  It was discovered that the PHP XSL extension did not restrict the file
  writing capability of libxslt. A remote attacker could use this flaw to
  create or overwrite an arbitrary file that is writable by the user running
  PHP, if a PHP script processed untrusted eXtensible Style Sheet Language
  Transformations (XSLT) content. (CVE-2012-0057)

  Note: This update disables file writing by default. A new PHP configuration
  directive, 'xsl.security_prefs', can be used to enable file writing in
  XSLT.

  A flaw was found in the way PHP validated file names in file upload
  requests. A remote attacker could possibly use this flaw to bypass the
  sanitization of the uploaded file names, and cause a PHP script to store
  the uploaded file in an unexpected directory, by using a directory
  traversal attack. (CVE-2012-1172)

  Multiple integer overflow flaws, leading to heap-based buffer overflows,
  were found in the way the PHP phar extension processed certain fields of
  tar archive files. A remote attacker could provide a specially-crafted tar
  archive file that, when processed by a PHP application using the phar
  extension, could cause the application to crash or, potentially, execute
  arbitrary code with the privileges of the user running PHP. (CVE-2012-2386)

  A format string flaw was found in the way the PHP phar extension processed
  certain PHAR files. A remote attacker could provide a specially-crafted
  PHAR file, which once processed in a PHP application using the phar
  extension, could lead to information disclosure and possibly arbitrary code
  execution via a crafted phar:// URI. (CVE-2010-2950)

  A flaw was found in the DES algorithm implementation in the crypt()
  password hashing function in PHP. If the password string to be hashed
  contained certain characters, the remainder of the string was ignored when
  calculating the hash, significantly reducing the password strength.
  (CVE-2012-2143)

  Note: With this update, passwords are no longer truncated when performing
  DES hashing. Therefore, new hashes of the affected passwords will not match
  stored hashes generated using vulnerable PHP versions, and will need to be
  updated.

  It was discovered that the fix for CVE-2012-1823, released via
  RHSA-2012:0547, did not properly filter all php-cgi command line arguments.
  A specially-crafted request to a PHP script could cause the PHP interpreter
  to execute the script in a loop, or output usage information that triggers
  an Internal Server Error. (CVE-2012 ...

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

  if ((res = isrpmvuln(pkg:"php53", rpm:"php53~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-bcmath", rpm:"php53-bcmath~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-cli", rpm:"php53-cli~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-common", rpm:"php53-common~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-dba", rpm:"php53-dba~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-devel", rpm:"php53-devel~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-gd", rpm:"php53-gd~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-imap", rpm:"php53-imap~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-intl", rpm:"php53-intl~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-ldap", rpm:"php53-ldap~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-mbstring", rpm:"php53-mbstring~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-mysql", rpm:"php53-mysql~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-odbc", rpm:"php53-odbc~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-pdo", rpm:"php53-pdo~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-pgsql", rpm:"php53-pgsql~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-process", rpm:"php53-process~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-pspell", rpm:"php53-pspell~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-snmp", rpm:"php53-snmp~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-soap", rpm:"php53-soap~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-xml", rpm:"php53-xml~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-xmlrpc", rpm:"php53-xmlrpc~5.3.3~13.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
