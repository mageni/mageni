###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for php53 RHSA-2013:1307-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871047");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-10-03 10:17:21 +0530 (Thu, 03 Oct 2013)");
  script_cve_id("CVE-2006-7243", "CVE-2011-1398", "CVE-2012-0831", "CVE-2012-2688",
                "CVE-2013-1643", "CVE-2013-4248");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for php53 RHSA-2013:1307-01");


  script_tag(name:"affected", value:"php53 on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"insight", value:"PHP is an HTML-embedded scripting language commonly used with the Apache
HTTP Server.

It was found that PHP did not properly handle file names with a NULL
character. A remote attacker could possibly use this flaw to make a PHP
script access unexpected files and bypass intended file system access
restrictions. (CVE-2006-7243)

It was found that PHP did not check for carriage returns in HTTP headers,
allowing intended HTTP response splitting protections to be bypassed.
Depending on the web browser the victim is using, a remote attacker could
use this flaw to perform HTTP response splitting attacks. (CVE-2011-1398)

A flaw was found in PHP's SSL client's hostname identity check when
handling certificates that contain hostnames with NULL bytes. If an
attacker was able to get a carefully crafted certificate signed by a
trusted Certificate Authority, the attacker could use the certificate to
conduct man-in-the-middle attacks to spoof SSL servers. (CVE-2013-4248)

An integer signedness issue, leading to a heap-based buffer underflow, was
found in the PHP scandir() function. If a remote attacker could upload an
excessively large number of files to a directory the scandir() function
runs on, it could cause the PHP interpreter to crash or, possibly, execute
arbitrary code. (CVE-2012-2688)

It was found that PHP did not correctly handle the magic_quotes_gpc
configuration directive. This could result in magic_quotes_gpc input
escaping not being applied in all cases, possibly making it easier for a
remote attacker to perform SQL injection attacks. (CVE-2012-0831)

It was found that the PHP SOAP parser allowed the expansion of external XML
entities during SOAP message parsing. A remote attacker could possibly use
this flaw to read arbitrary files that are accessible to a PHP application
using a SOAP extension. (CVE-2013-1643)

These updated php53 packages also include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 5.10 Technical
Notes, linked to in the References, for information on the most significant
of these changes.

All PHP users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add this
enhancement. After installing the updated packages, the httpd daemon must
be restarted for the update to take effect.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-September/msg00050.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'php53'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"php53", rpm:"php53~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-bcmath", rpm:"php53-bcmath~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-cli", rpm:"php53-cli~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-common", rpm:"php53-common~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-dba", rpm:"php53-dba~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-debuginfo", rpm:"php53-debuginfo~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-devel", rpm:"php53-devel~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-gd", rpm:"php53-gd~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-imap", rpm:"php53-imap~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-intl", rpm:"php53-intl~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-ldap", rpm:"php53-ldap~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-mbstring", rpm:"php53-mbstring~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-mysql", rpm:"php53-mysql~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-odbc", rpm:"php53-odbc~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-pdo", rpm:"php53-pdo~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-pgsql", rpm:"php53-pgsql~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-process", rpm:"php53-process~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-pspell", rpm:"php53-pspell~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-snmp", rpm:"php53-snmp~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-soap", rpm:"php53-soap~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-xml", rpm:"php53-xml~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-xmlrpc", rpm:"php53-xmlrpc~5.3.3~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
