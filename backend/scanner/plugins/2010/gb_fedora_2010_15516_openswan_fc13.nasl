###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for openswan FEDORA-2010-15516
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
tag_insight = "Openswan is a free implementation of IPsec &amp; IKE for Linux.  IPsec is
  the Internet Protocol Security and uses strong cryptography to provide
  both authentication and encryption services.  These services allow you
  to build secure tunnels through untrusted networks.  Everything passing
  through the untrusted net is encrypted by the ipsec gateway machine and
  decrypted by the gateway at the other end of the tunnel.  The resulting
  tunnel is a virtual private network or VPN.

  This package contains the daemons and userland tools for setting up
  Openswan. It supports the NETKEY/XFRM IPsec kernel stack that exists
  in the default Linux kernel.
  
  Openswan 2.6.x also supports IKEv2 (RFC4306)";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "openswan on Fedora 13";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-October/049073.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313446");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-19 15:54:15 +0200 (Tue, 19 Oct 2010)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2010-15516");
  script_cve_id("CVE-2010-3308", "CVE-2010-3302");
  script_name("Fedora Update for openswan FEDORA-2010-15516");

  script_tag(name: "summary" , value: "Check for the Version of openswan");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC13")
{

  if ((res = isrpmvuln(pkg:"openswan", rpm:"openswan~2.6.29~1.fc13", rls:"FC13")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
