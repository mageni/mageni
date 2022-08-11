###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for php CESA-2010:0919 centos4 i386
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
tag_insight = "PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Server.

  An input validation flaw was discovered in the PHP session serializer. If a
  PHP script generated session variable names from untrusted user input, a
  remote attacker could use this flaw to inject an arbitrary variable into
  the PHP session. (CVE-2010-3065)
  
  An information leak flaw was discovered in the PHP var_export() function
  implementation. If some fatal error occurred during the execution of this
  function (such as the exhaustion of memory or script execution time limit),
  part of the function's output was sent to the user as script output,
  possibly leading to the disclosure of sensitive information.
  (CVE-2010-2531)
  
  A numeric truncation error and an input validation flaw were found in the
  way the PHP utf8_decode() function decoded partial multi-byte sequences
  for some multi-byte encodings, sending them to output without them being
  escaped. An attacker could use these flaws to perform a cross-site
  scripting attack. (CVE-2009-5016, CVE-2010-3870)
  
  It was discovered that the PHP lcg_value() function used insufficient
  entropy to seed the pseudo-random number generator. A remote attacker could
  possibly use this flaw to predict values returned by the function, which
  are used to generate session identifiers by default. This update changes
  the function's implementation to use more entropy during seeding.
  (CVE-2010-1128)
  
  It was discovered that the PHP fnmatch() function did not restrict the
  length of the pattern argument. A remote attacker could use this flaw to
  crash the PHP interpreter where a script used fnmatch() on untrusted
  matching patterns. (CVE-2010-1917)
  
  A NULL pointer dereference flaw was discovered in the PHP XML-RPC
  extension. A malicious XML-RPC client or server could use this flaw to
  crash the PHP interpreter via a specially-crafted XML-RPC request.
  (CVE-2010-0397)
  
  All php users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. After installing the updated
  packages, the httpd daemon must be restarted for the update to take effect.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "php on CentOS 4";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-December/017205.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313767");
  script_version("$Revision: 8269 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-02 08:28:22 +0100 (Tue, 02 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-12-09 08:26:35 +0100 (Thu, 09 Dec 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-5016", "CVE-2010-0397", "CVE-2010-1128", "CVE-2010-1917", "CVE-2010-2531", "CVE-2010-3065", "CVE-2010-3870");
  script_name("CentOS Update for php CESA-2010:0919 centos4 i386");

  script_tag(name: "summary" , value: "Check for the Version of php");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"php", rpm:"php~4.3.9~3.31", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~4.3.9~3.31", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-domxml", rpm:"php-domxml~4.3.9~3.31", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~4.3.9~3.31", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-imap", rpm:"php-imap~4.3.9~3.31", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~4.3.9~3.31", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~4.3.9~3.31", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mysql", rpm:"php-mysql~4.3.9~3.31", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-ncurses", rpm:"php-ncurses~4.3.9~3.31", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~4.3.9~3.31", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear", rpm:"php-pear~4.3.9~3.31", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~4.3.9~3.31", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~4.3.9~3.31", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-xmlrpc", rpm:"php-xmlrpc~4.3.9~3.31", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
