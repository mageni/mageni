###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for php CESA-2008:0544 centos3 i386
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
  
  PHP functions htmlentities() and htmlspecialchars() did not properly
  recognize partial multi-byte sequences. Certain sequences of bytes could be
  passed through these functions without being correctly HTML-escaped.
  Depending on the browser being used, an attacker could use this flaw to
  conduct cross-site scripting attacks. (CVE-2007-5898)
  
  A PHP script which used the transparent session ID configuration option, or
  which used the output_add_rewrite_var() function, could leak session
  identifiers to external web sites. If a page included an HTML form with an
  ACTION attribute referencing a non-local URL, the user's session ID would
  be included in the form data passed to that URL. (CVE-2007-5899)
  
  It was discovered that PHP fnmatch() function did not restrict the length
  of the string argument. An attacker could use this flaw to crash the PHP
  interpreter where a script used fnmatch() on untrusted input data.
  (CVE-2007-4782)
  
  It was discovered that PHP did not properly seed its pseudo-random number
  generator used by functions such as rand() and mt_rand(), possibly allowing
  an attacker to easily predict the generated pseudo-random values.
  (CVE-2008-2107, CVE-2008-2108)
  
  Users of PHP should upgrade to these updated packages, which contain
  backported patches to correct these issues.";

tag_affected = "php on CentOS 3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-July/015128.html");
  script_oid("1.3.6.1.4.1.25623.1.0.308219");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:40:14 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2051", "CVE-2007-5898", "CVE-2007-5899", "CVE-2007-4782", "CVE-2008-2107", "CVE-2008-2108");
  script_name( "CentOS Update for php CESA-2008:0544 centos3 i386");

  script_tag(name:"summary", value:"Check for the Version of php");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"php", rpm:"php~4.3.2~48.ent", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~4.3.2~48.ent", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-imap", rpm:"php-imap~4.3.2~48.ent", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~4.3.2~48.ent", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mysql", rpm:"php-mysql~4.3.2~48.ent", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~4.3.2~48.ent", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~4.3.2~48.ent", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
