###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for squirrelmail MDVSA-2010:120 (squirrelmail)
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
tag_insight = "A vulnerability was reported in the SquirrelMail Mail Fetch plugin,
  wherein (when the plugin is activated by the administrator) a user
  is allowed to specify (without restriction) any port number for their
  external POP account settings. While the intention is to allow users
  to access POP3 servers using non-standard ports, this also allows
  malicious users to effectively port-scan any server through their
  SquirrelMail service (especially note that when a SquirrelMail server
  resides on a network behind a firewall, it may allow the user to
  explore the network topography (DNS scan) and services available
  (port scan) on the inside of (behind) that firewall). As this
  vulnerability is only exploitable post-authentication, and better
  more specific port scanning tools are freely available, we consider
  this vulnerability to be of very low severity. It has been fixed by
  restricting the allowable POP port numbers (with an administrator
  configuration override available) (CVE-2010-1637).

  The updated packages have been patched to correct this issue.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "squirrelmail on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-06/msg00023.php");
  script_oid("1.3.6.1.4.1.25623.1.0.312886");
  script_version("$Revision: 8258 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-29 08:28:57 +0100 (Fri, 29 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-06-25 12:25:26 +0200 (Fri, 25 Jun 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_xref(name: "MDVSA", value: "2010:120");
  script_cve_id("CVE-2010-1637");
  script_name("Mandriva Update for squirrelmail MDVSA-2010:120 (squirrelmail)");

  script_tag(name: "summary" , value: "Check for the Version of squirrelmail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ar", rpm:"squirrelmail-ar~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-bg", rpm:"squirrelmail-bg~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-bn", rpm:"squirrelmail-bn~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ca", rpm:"squirrelmail-ca~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-cs", rpm:"squirrelmail-cs~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-cy", rpm:"squirrelmail-cy~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-cyrus", rpm:"squirrelmail-cyrus~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-da", rpm:"squirrelmail-da~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-de", rpm:"squirrelmail-de~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-el", rpm:"squirrelmail-el~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-en", rpm:"squirrelmail-en~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-es", rpm:"squirrelmail-es~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-et", rpm:"squirrelmail-et~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-eu", rpm:"squirrelmail-eu~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-fa", rpm:"squirrelmail-fa~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-fi", rpm:"squirrelmail-fi~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-fo", rpm:"squirrelmail-fo~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-fr", rpm:"squirrelmail-fr~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-fy", rpm:"squirrelmail-fy~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-he", rpm:"squirrelmail-he~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-hr", rpm:"squirrelmail-hr~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-hu", rpm:"squirrelmail-hu~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-id", rpm:"squirrelmail-id~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-is", rpm:"squirrelmail-is~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-it", rpm:"squirrelmail-it~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ja", rpm:"squirrelmail-ja~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ka", rpm:"squirrelmail-ka~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ko", rpm:"squirrelmail-ko~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-lt", rpm:"squirrelmail-lt~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ms", rpm:"squirrelmail-ms~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-nb", rpm:"squirrelmail-nb~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-nl", rpm:"squirrelmail-nl~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-nn", rpm:"squirrelmail-nn~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-pl", rpm:"squirrelmail-pl~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-poutils", rpm:"squirrelmail-poutils~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-pt", rpm:"squirrelmail-pt~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ro", rpm:"squirrelmail-ro~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ru", rpm:"squirrelmail-ru~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-sk", rpm:"squirrelmail-sk~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-sl", rpm:"squirrelmail-sl~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-sr", rpm:"squirrelmail-sr~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-sv", rpm:"squirrelmail-sv~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-th", rpm:"squirrelmail-th~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-tr", rpm:"squirrelmail-tr~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ug", rpm:"squirrelmail-ug~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-uk", rpm:"squirrelmail-uk~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-vi", rpm:"squirrelmail-vi~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-zh_CN", rpm:"squirrelmail-zh_CN~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-zh_TW", rpm:"squirrelmail-zh_TW~1.4.19~2.3mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
