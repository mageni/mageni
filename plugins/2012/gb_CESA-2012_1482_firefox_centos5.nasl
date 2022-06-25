###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for firefox CESA-2012:1482 centos5
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-November/019003.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881544");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-11-23 11:48:48 +0530 (Fri, 23 Nov 2012)");
  script_cve_id("CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4207", "CVE-2012-4209",
                "CVE-2012-4210", "CVE-2012-4214", "CVE-2012-4215", "CVE-2012-4216",
                "CVE-2012-5829", "CVE-2012-5830", "CVE-2012-5833", "CVE-2012-5835",
                "CVE-2012-5839", "CVE-2012-5840", "CVE-2012-5841", "CVE-2012-5842");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for firefox CESA-2012:1482 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"firefox on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser. XULRunner provides the
  XUL Runtime environment for Mozilla Firefox.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2012-4214, CVE-2012-4215, CVE-2012-4216, CVE-2012-5829,
  CVE-2012-5830, CVE-2012-5833, CVE-2012-5835, CVE-2012-5839, CVE-2012-5840,
  CVE-2012-5842)

  A buffer overflow flaw was found in the way Firefox handled GIF (Graphics
  Interchange Format) images. A web page containing a malicious GIF image
  could cause Firefox to crash or, possibly, execute arbitrary code with the
  privileges of the user running Firefox. (CVE-2012-4202)

  A flaw was found in the way the Style Inspector tool in Firefox handled
  certain Cascading Style Sheets (CSS). Running the tool (Tools -> Web
  Developer -> Inspect) on malicious CSS could result in the execution of
  HTML and CSS content with chrome privileges. (CVE-2012-4210)

  A flaw was found in the way Firefox decoded the HZ-GB-2312 character
  encoding. A web page containing malicious content could cause Firefox to
  run JavaScript code with the permissions of a different website.
  (CVE-2012-4207)

  A flaw was found in the location object implementation in Firefox.
  Malicious content could possibly use this flaw to allow restricted content
  to be loaded by plug-ins. (CVE-2012-4209)

  A flaw was found in the way cross-origin wrappers were implemented.
  Malicious content could use this flaw to perform cross-site scripting
  attacks. (CVE-2012-5841)

  A flaw was found in the evalInSandbox implementation in Firefox. Malicious
  content could use this flaw to perform cross-site scripting attacks.
  (CVE-2012-4201)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 10.0.11 ESR. You can find a link to the Mozilla
  advisories in the References section of this erratum.

  Red Hat would like to thank the Mozilla project for reporting these issues.
  Upstream acknowledges Abhishek Arya, miaubiz, Jesse Ruderman, Andrew
  McCreight, Bob Clary, Kyle Huey, Atte Kettunen, Mariusz Mlynski, Masato
  Kinugawa, Bobby Holley, and moz_bug_r_a4 as the original reporters of these
  issues.

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 10.0.11 ESR, which corrects these issues. After installing
  the update, Firefox must be restarted for the changes to take effect.");
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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~10.0.11~1.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~10.0.11~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~10.0.11~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
