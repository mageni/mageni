###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for firefox RHSA-2008:0103-01
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
tag_insight = "Mozilla Firefox is an open source Web browser.

  Several flaws were found in the way Firefox processed certain malformed web
  content. A webpage containing malicious content could cause Firefox to
  crash, or potentially execute arbitrary code as the user running Firefox.
  (CVE-2008-0412, CVE-2008-0413, CVE-2008-0415, CVE-2008-0419)
  
  Several flaws were found in the way Firefox displayed malformed web
  content. A webpage containing specially-crafted content could trick a user
  into surrendering sensitive information. (CVE-2008-0591, CVE-2008-0593)
  
  A flaw was found in the way Firefox stored password data. If a user saves
  login information for a malicious website, it could be possible to corrupt
  the password database, preventing the user from properly accessing saved
  password data. (CVE-2008-0417)
  
  A flaw was found in the way Firefox handles certain chrome URLs. If a user
  has certain extensions installed, it could allow a malicious website to
  steal sensitive session data. Note: this flaw does not affect a default
  installation of Firefox. (CVE-2008-0418)
  
  A flaw was found in the way Firefox saves certain text files. If a
  website offers a file of type &quot;plain/text&quot;, rather than &quot;text/plain&quot;,
  Firefox will not show future &quot;text/plain&quot; content to the user in the
  browser, forcing them to save those files locally to view the content.
  (CVE-2008-0592) 
  
  Users of firefox are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.";

tag_affected = "firefox on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4,
  Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-February/msg00001.html");
  script_oid("1.3.6.1.4.1.25623.1.0.311147");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2008:0103-01");
  script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0415", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593");
  script_name( "RedHat Update for firefox RHSA-2008:0103-01");

  script_tag(name:"summary", value:"Check for the Version of firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~1.5.0.12~9.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~1.5.0.12~9.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-devel", rpm:"firefox-devel~1.5.0.12~9.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~1.5.0.12~0.10.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~1.5.0.12~0.10.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
