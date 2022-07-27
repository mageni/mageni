###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for enscript CESA-2008:1021-02 centos2 i386
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
tag_insight = "GNU enscript converts ASCII files to PostScript(R) language files and
  spools the generated output to a specified printer or saves it to a file.
  Enscript can be extended to handle different output media and includes
  options for customizing printouts.

  Several buffer overflow flaws were found in GNU enscript. An attacker could
  craft an ASCII file in such a way that it could execute arbitrary commands
  if the file was opened with enscript with the &quot;special escapes&quot; option (-e
  or --escapes) enabled. (CVE-2008-3863, CVE-2008-4306, CVE-2008-5078)
  
  All users of enscript should upgrade to these updated packages, which
  contain backported patches to correct these issues.";

tag_affected = "enscript on CentOS 2";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-December/015486.html");
  script_oid("1.3.6.1.4.1.25623.1.0.304724");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:36:45 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-3863", "CVE-2008-4306", "CVE-2008-5078");
  script_name( "CentOS Update for enscript CESA-2008:1021-02 centos2 i386");

  script_tag(name:"summary", value:"Check for the Version of enscript");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS2")
{

  if ((res = isrpmvuln(pkg:"enscript", rpm:"enscript~1.6.1~16.7", rls:"CentOS2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
