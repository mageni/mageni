###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for awstats FEDORA-2008-7684
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
tag_insight = "Advanced Web Statistics is a powerful and featureful tool that generates
  advanced web server graphic statistics. This server log analyzer works
  from command line or as a CGI and shows you all information your log contains,
  in graphical web pages. It can analyze a lot of web/wap/proxy servers like
  Apache, IIS, Weblogic, Webstar, Squid, ... but also mail or ftp servers.

  This program can measure visits, unique visitors, authenticated users, pages,
  domains/countries, OS busiest times, robot visits, type of files, search
  engines/keywords used, visits duration, HTTP errors and more...
  Statistics can be updated from a browser or your scheduler.
  The program also supports virtual servers, plugins and a lot of features.
  
  With the default configuration, the statistics are available:
  <a  rel= &qt nofollow &qt  href= &qt http://localhost/awstats/awstats.pl &qt >http://localhost/awstats/awstats.pl</a>";

tag_affected = "awstats on Fedora 8";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2008-September/msg00355.html");
  script_oid("1.3.6.1.4.1.25623.1.0.311279");
  script_version("$Revision: 6623 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:10:20 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-17 17:03:12 +0100 (Tue, 17 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "FEDORA", value: "2008-7684");
  script_cve_id("CVE-2008-3714");
  script_name( "Fedora Update for awstats FEDORA-2008-7684");

  script_tag(name:"summary", value:"Check for the Version of awstats");
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

  if ((res = isrpmvuln(pkg:"awstats", rpm:"awstats~6.8~2.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
