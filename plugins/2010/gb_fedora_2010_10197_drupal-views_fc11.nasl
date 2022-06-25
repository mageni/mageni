###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for drupal-views FEDORA-2010-10197
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
tag_insight = "The views module provides a flexible method for Drupal site designers
  to control how lists of content (nodes) are presented. Traditionally,
  Drupal has hard-coded most of this, particularly in how taxonomy and
  tracker lists are formatted.

  This tool is essentially a smart query builder that, given enough
  information, can build the proper query, execute it, and display the
  results. It has four modes, plus a special mode, and provides an
  impressive amount of functionality from these modes.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "drupal-views on Fedora 11";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-June/043188.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314371");
  script_version("$Revision: 8495 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-25 12:25:26 +0200 (Fri, 25 Jun 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2010-10197");
  script_name("Fedora Update for drupal-views FEDORA-2010-10197");

  script_tag(name: "summary" , value: "Check for the Version of drupal-views");
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

  if ((res = isrpmvuln(pkg:"drupal-views", rpm:"drupal-views~6.x.2.11~1.fc11", rls:"FC11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
