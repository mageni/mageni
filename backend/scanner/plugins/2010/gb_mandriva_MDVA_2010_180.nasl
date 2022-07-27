###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for nss_ldap MDVA-2010:180 (nss_ldap)
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
tag_affected = "nss_ldap on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";
tag_insight = "nss_ldap is now provided with krb5_ccname as compilation option.";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-07/msg00005.php");
  script_oid("1.3.6.1.4.1.25623.1.0.313833");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-07-12 11:56:20 +0200 (Mon, 12 Jul 2010)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_xref(name: "MDVA", value: "2010:180");
  script_name("Mandriva Update for nss_ldap MDVA-2010:180 (nss_ldap)");

  script_tag(name: "summary" , value: "Check for the Version of nss_ldap");
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

  if ((res = isrpmvuln(pkg:"nss_ldap-262", rpm:"nss_ldap-262~4.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
