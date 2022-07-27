###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for rsh MDVA-2010:186 (rsh)
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
tag_affected = "rsh on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64";
tag_insight = "Various packages of old unix utilities (rsh, rlogin, telnet,
  ...) available in mandriva used to be paralleously installable, though
  usage of setup-alternative utility. In 2010.1, the MIT-kerberized
  versions from krb5-appl package ceased to use this setup, for sake of
  simplicity, and was made conflicting with other packages. However,
  the netkit version of rsh wasn't modified accordingly, and still
  install its binaries as {rsh,rlogin,telnet}.netkit, making their
  usage impractical.";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-08/msg00013.php");
  script_oid("1.3.6.1.4.1.25623.1.0.313071");
  script_version("$Revision: 8244 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-09-27 08:14:44 +0200 (Mon, 27 Sep 2010)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_xref(name: "MDVA", value: "2010:186");
  script_name("Mandriva Update for rsh MDVA-2010:186 (rsh)");

  script_tag(name: "summary" , value: "Check for the Version of rsh");
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

if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"rsh", rpm:"rsh~0.17~26.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rsh-server", rpm:"rsh-server~0.17~26.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
