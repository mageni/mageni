###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for tomcat5 FEDORA-2008-8130
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
tag_insight = "Tomcat is the servlet container that is used in the official Reference
  Implementation for the Java Servlet and JavaServer Pages technologies.
  The Java Servlet and JavaServer Pages specifications are developed by
  Sun under the Java Community Process.

  Tomcat is developed in an open and participatory environment and
  released under the Apache Software License. Tomcat is intended to be
  a collaboration of the best-of-breed developers from around the world.
  We invite you to participate in this open development project. To
  learn more about getting involved, click here.";

tag_affected = "tomcat5 on Fedora 8";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2008-September/msg00889.html");
  script_oid("1.3.6.1.4.1.25623.1.0.305931");
  script_version("$Revision: 6623 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:10:20 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-17 17:05:11 +0100 (Tue, 17 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_xref(name: "FEDORA", value: "2008-8130");
  script_cve_id("CVE-2007-5342", "CVE-2007-5333", "CVE-2007-5461", "CVE-2007-6286", "CVE-2007-1355", "CVE-2007-3386", "CVE-2007-3385", "CVE-2007-3382", "CVE-2007-2450", "CVE-2007-2449", "CVE-2007-1358", "CVE-2008-1232", "CVE-2008-1947", "CVE-2008-2370", "CVE-2008-2938");
  script_name( "Fedora Update for tomcat5 FEDORA-2008-8130");

  script_tag(name:"summary", value:"Check for the Version of tomcat5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC8")
{

  if ((res = isrpmvuln(pkg:"tomcat5", rpm:"tomcat5~5.5.27~0jpp.2.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
