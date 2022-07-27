###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for php-ZendFramework FEDORA-2010-0652
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
tag_affected = "php-ZendFramework on Fedora 12";
tag_insight = "Extending the art &amp; spirit of PHP, Zend Framework is based on simplicity,
  object-oriented best practices, corporate friendly licensing, and a rigorously
  tested agile codebase. Zend Framework is focused on building more secure,
  reliable, and modern Web 2.0 applications &amp; web services, and consuming widely
  available APIs from leading vendors like Google, Amazon, Yahoo!, Flickr, as
  well as API providers and catalogers like StrikeIron and ProgrammableWeb.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-January/034021.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314732");
  script_version("$Revision: 8228 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-03-02 08:38:02 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "FEDORA", value: "2010-0652");
  script_name("Fedora Update for php-ZendFramework FEDORA-2010-0652");

  script_tag(name: "summary" , value: "Check for the Version of php-ZendFramework");
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

if(release == "FC12")
{

  if ((res = isrpmvuln(pkg:"php-ZendFramework", rpm:"php-ZendFramework~1.9.7~1.fc12", rls:"FC12")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
