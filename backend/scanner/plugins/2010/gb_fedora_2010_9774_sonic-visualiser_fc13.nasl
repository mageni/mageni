###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for sonic-visualiser FEDORA-2010-9774
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
tag_insight = "Sonic Visualiser is an application for viewing and analysing the
  contents of music audio files.

  The aim of Sonic Visualiser is to be the first program you reach for
  when want to study a musical recording rather than simply listen to
  it.
  
  As well as a number of features designed to make exploring audio data
  as revealing and fun as possible, Sonic Visualiser also has powerful
  annotation capabilities to help you to describe what you find, and the
  ability to run automated annotation and analysis plugins in the Vamp
  analysis plugin format &#8211; as well as applying standard audio effects.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "sonic-visualiser on Fedora 13";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-June/042716.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313121");
  script_version("$Revision: 8266 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-01 08:28:32 +0100 (Mon, 01 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-11 13:46:51 +0200 (Fri, 11 Jun 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2010-9774");
  script_cve_id("CVE-2009-3377");
  script_name("Fedora Update for sonic-visualiser FEDORA-2010-9774");

  script_tag(name: "summary" , value: "Check for the Version of sonic-visualiser");
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

  if ((res = isrpmvuln(pkg:"sonic-visualiser", rpm:"sonic-visualiser~1.7.2~1.fc13", rls:"FC13")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
