###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for mmc MDVA-2010:044 (mmc)
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
tag_insight = "This is a bundle of MDS related packages that fixes numerous bugs.

  mmc-agent:
  * Fix password injection in LDIF file when running adduser hook
  * Set default value of shadowExpire to -1 to avoid account expiration
  messages
  * Fix bad peer reported by the connection debug message
  * Fix provisioning when authenticating using the local LDAP
  * Support for RFC3062 extended password change operation
  * The MDVA-2009:216 update caused regressions that is now fixed
  (#55912):
  * use %%py_puresitedir instead of %%py_platsitedir (misc)
  * remove arch dependent references
  
  mmc-web-base:
  * fix MMC login page with regards to the connect button and the
  language select widget
  * Update to scriptaculous V 1.8.3 (correct some problems when using
  with IE)
  * Ask web browser not to autocomplete input fields #52654
  * Fix password update bug #52654
  * New icons needed for Pulse 2
  
  mmc-web-network:
  * French translation update #52936
  * Spanish translation update
  
  mmc-web-samba:
  * French translation update #52936
  
  mmc-wizard:
  * fixes a typo error in mds.ini: shadowExpore instead of shadowExpire
  in [userDefault] (#57249).";

tag_affected = "mmc on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-01/msg00081.php");
  script_oid("1.3.6.1.4.1.25623.1.0.314800");
  script_version("$Revision: 8457 $");
  script_cve_id("CVE-2008-7247");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-01-29 14:09:25 +0100 (Fri, 29 Jan 2010)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_xref(name: "MDVA", value: "2010:044");
  script_name("Mandriva Update for mmc MDVA-2010:044 (mmc)");

  script_tag(name: "summary" , value: "Check for the Version of mmc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"mmc-agent", rpm:"mmc-agent~2.3.2~0.5mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mmc-web-base", rpm:"mmc-web-base~2.3.2~0.3mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mmc-web-network", rpm:"mmc-web-network~2.3.2~0.3mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mmc-web-samba", rpm:"mmc-web-samba~2.3.2~0.3mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mmc-wizard", rpm:"mmc-wizard~1.0~13.4mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-mmc-base", rpm:"python-mmc-base~2.3.2~0.5mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-mmc-mail", rpm:"python-mmc-mail~2.3.2~0.5mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-mmc-network", rpm:"python-mmc-network~2.3.2~0.5mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-mmc-proxy", rpm:"python-mmc-proxy~2.3.2~0.5mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-mmc-samba", rpm:"python-mmc-samba~2.3.2~0.5mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
