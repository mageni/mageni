###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for php RHSA-2008:0545-01
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
tag_insight = "PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Web server.

  It was discovered that the PHP escapeshellcmd() function did not properly
  escape multi-byte characters which are not valid in the locale used by the
  script. This could allow an attacker to bypass quoting restrictions imposed
  by escapeshellcmd() and execute arbitrary commands if the PHP script was
  using certain locales. Scripts using the default UTF-8 locale are not
  affected by this issue. (CVE-2008-2051)
  
  The PHP functions htmlentities() and htmlspecialchars() did not properly
  recognize partial multi-byte sequences. Certain sequences of bytes could be
  passed through these functions without being correctly HTML-escaped.
  Depending on the browser being used, an attacker could use this flaw to
  conduct cross-site scripting attacks. (CVE-2007-5898)
  
  A PHP script which used the transparent session ID configuration option, or
  which used the output_add_rewrite_var() function, could leak session
  identifiers to external web sites. If a page included an HTML form with an
  ACTION attribute referencing a non-local URL, the user's session ID would
  be included in the form data passed to that URL. (CVE-2007-5899)
  
  It was discovered that the PHP fnmatch() function did not restrict the
  length of the string argument. An attacker could use this flaw to crash the
  PHP interpreter where a script used fnmatch() on untrusted input data.
  (CVE-2007-4782)
  
  It was discovered that PHP did not properly seed its pseudo-random number
  generator used by functions such as rand() and mt_rand(), possibly allowing
  an attacker to easily predict the generated pseudo-random values.
  (CVE-2008-2107, CVE-2008-2108)
  
  As well, these updated packages fix the following bug:
  
  * after 2008-01-01, when using PEAR version 1.3.6 or older, it was not
  possible to use the PHP Extension and Application Repository (PEAR) to
  upgrade or install packages. In these updated packages, PEAR has been
  upgraded to version 1.4.9, which restores support for the current
  pear.php.net update server. The following changes were made to the PEAR
  packages included in php-pear: Console_Getopt and Archive_Tar are now
  included by default, and XML_RPC has been upgraded to version 1.5.0.
  
  All php users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.";

tag_affected = "php on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-July/msg00017.html");
  script_oid("1.3.6.1.4.1.25623.1.0.309650");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2008:0545-01");
  script_cve_id("CVE-2008-2051", "CVE-2007-5898", "CVE-2007-5899", "CVE-2007-4782", "CVE-2008-2107", "CVE-2008-2108");
  script_name( "RedHat Update for php RHSA-2008:0545-01");

  script_tag(name:"summary", value:"Check for the Version of php");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"php", rpm:"php~4.3.9~3.22.12", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-debuginfo", rpm:"php-debuginfo~4.3.9~3.22.12", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~4.3.9~3.22.12", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-domxml", rpm:"php-domxml~4.3.9~3.22.12", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~4.3.9~3.22.12", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-imap", rpm:"php-imap~4.3.9~3.22.12", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~4.3.9~3.22.12", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~4.3.9~3.22.12", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mysql", rpm:"php-mysql~4.3.9~3.22.12", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-ncurses", rpm:"php-ncurses~4.3.9~3.22.12", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~4.3.9~3.22.12", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear", rpm:"php-pear~4.3.9~3.22.12", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~4.3.9~3.22.12", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~4.3.9~3.22.12", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-xmlrpc", rpm:"php-xmlrpc~4.3.9~3.22.12", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
