###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for htdig FEDORA-2007-757
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
tag_insight = "The ht://Dig system is a complete world wide web indexing and searching
  system for a small domain or intranet. This system is not meant to replace
  the need for powerful internet-wide search systems like Lycos, Infoseek,
  Webcrawler and AltaVista. Instead it is meant to cover the search needs for
  a single company, campus, or even a particular sub section of a web site. As
  opposed to some WAIS-based or web-server based search engines, ht://Dig can
  span several web servers at a site. The type of these different web servers
  doesn't matter as long as they understand the HTTP 1.0 protocol.
  ht://Dig is also used by KDE to search KDE's HTML documentation.

  ht://Dig was developed at San Diego State University as a way to search the
  various web servers on the campus network.";

tag_affected = "htdig on Fedora Core 6";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-December/msg00116.html");
  script_oid("1.3.6.1.4.1.25623.1.0.310110");
  script_version("$Revision: 6622 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 07:52:50 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:31:39 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "FEDORA", value: "2007-757");
  script_cve_id("CVE-2007-6110");
  script_name( "Fedora Update for htdig FEDORA-2007-757");

  script_tag(name:"summary", value:"Check for the Version of htdig");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora_core", "ssh/login/rpms");
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

if(release == "FC6")
{

  if ((res = isrpmvuln(pkg:"htdig", rpm:"htdig~3.2.0b6~9.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/htdig-web", rpm:"x86_64/htdig-web~3.2.0b6~9.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/htdig-debuginfo", rpm:"x86_64/debug/htdig-debuginfo~3.2.0b6~9.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/htdig", rpm:"x86_64/htdig~3.2.0b6~9.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/htdig-debuginfo", rpm:"i386/debug/htdig-debuginfo~3.2.0b6~9.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/htdig-web", rpm:"i386/htdig-web~3.2.0b6~9.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/htdig", rpm:"i386/htdig~3.2.0b6~9.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
