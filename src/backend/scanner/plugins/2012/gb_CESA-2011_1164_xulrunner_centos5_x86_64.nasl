###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for xulrunner CESA-2011:1164 centos5 x86_64
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-September/018055.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881429");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:51:04 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-0084", "CVE-2011-2378", "CVE-2011-2981", "CVE-2011-2982",
                "CVE-2011-2983", "CVE-2011-2984");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for xulrunner CESA-2011:1164 centos5 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xulrunner'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"xulrunner on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2011-2982)

  A dangling pointer flaw was found in the Firefox Scalable Vector Graphics
  (SVG) text manipulation routine. A web page containing a malicious SVG
  image could cause Firefox to crash or, potentially, execute arbitrary code
  with the privileges of the user running Firefox. (CVE-2011-0084)

  A dangling pointer flaw was found in the way Firefox handled a certain
  Document Object Model (DOM) element. A web page containing malicious
  content could cause Firefox to crash or, potentially, execute arbitrary
  code with the privileges of the user running Firefox. (CVE-2011-2378)

  A flaw was found in the event management code in Firefox. A website
  containing malicious JavaScript could cause Firefox to execute that
  JavaScript with the privileges of the user running Firefox. (CVE-2011-2981)

  A flaw was found in the way Firefox handled malformed JavaScript. A web
  page containing malicious JavaScript could cause Firefox to access already
  freed memory, causing Firefox to crash or, potentially, execute arbitrary
  code with the privileges of the user running Firefox. (CVE-2011-2983)

  It was found that a malicious web page could execute arbitrary code with
  the privileges of the user running Firefox if the user dropped a tab onto
  the malicious web page. (CVE-2011-2984)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 3.6.20. You can find a link to the Mozilla
  advisories in the References section of this erratum.

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 3.6.20, which corrects these issues. After installing the
  update, Firefox must be restarted for the changes to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~1.9.2.20~2.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~1.9.2.20~2.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
