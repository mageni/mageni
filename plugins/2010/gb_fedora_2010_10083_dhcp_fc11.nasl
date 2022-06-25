###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for dhcp FEDORA-2010-10083
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
tag_insight = "DHCP (Dynamic Host Configuration Protocol) is a protocol which allows
  individual devices on an IP network to get their own network
  configuration information (IP address, subnetmask, broadcast address,
  etc.) from a DHCP server. The overall purpose of DHCP is to make it
  easier to administer a large network.  The dhcp package includes the
  ISC DHCP service and relay agent.

  To use DHCP on your network, install a DHCP service (or relay agent),
  and on clients run a DHCP client daemon.  The dhcp package provides
  the ISC DHCP service and relay agent.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "dhcp on Fedora 11";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-June/043344.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314712");
  script_version("$Revision: 8469 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-25 12:25:26 +0200 (Fri, 25 Jun 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2010-10083");
  script_cve_id("CVE-2010-2156", "CVE-2009-0692", "CVE-2009-1892");
  script_name("Fedora Update for dhcp FEDORA-2010-10083");

  script_tag(name: "summary" , value: "Check for the Version of dhcp");
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

if(release == "FC11")
{

  if ((res = isrpmvuln(pkg:"dhcp", rpm:"dhcp~4.1.0p1~6.fc11", rls:"FC11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
