###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for firefox CESA-2012:1210 centos5
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-August/018832.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881479");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-08-30 10:42:44 +0530 (Thu, 30 Aug 2012)");
  script_cve_id("CVE-2012-1970", "CVE-2012-1972", "CVE-2012-1973", "CVE-2012-1974",
                "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-3956", "CVE-2012-3957",
                "CVE-2012-3958", "CVE-2012-3959", "CVE-2012-3960", "CVE-2012-3961",
                "CVE-2012-3962", "CVE-2012-3963", "CVE-2012-3964", "CVE-2012-3966",
                "CVE-2012-3967", "CVE-2012-3968", "CVE-2012-3969", "CVE-2012-3970",
                "CVE-2012-3972", "CVE-2012-3976", "CVE-2012-3978", "CVE-2012-3980");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for firefox CESA-2012:1210 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"firefox on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  A web page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2012-1970, CVE-2012-1972, CVE-2012-1973, CVE-2012-1974,
  CVE-2012-1975, CVE-2012-1976, CVE-2012-3956, CVE-2012-3957, CVE-2012-3958,
  CVE-2012-3959, CVE-2012-3960, CVE-2012-3961, CVE-2012-3962, CVE-2012-3963,
  CVE-2012-3964)

  A web page containing a malicious Scalable Vector Graphics (SVG) image file
  could cause Firefox to crash or, potentially, execute arbitrary code with
  the privileges of the user running Firefox. (CVE-2012-3969, CVE-2012-3970)

  Two flaws were found in the way Firefox rendered certain images using
  WebGL. A web page containing malicious content could cause Firefox to crash
  or, under certain conditions, possibly execute arbitrary code with the
  privileges of the user running Firefox. (CVE-2012-3967, CVE-2012-3968)

  A flaw was found in the way Firefox decoded embedded bitmap images in Icon
  Format (ICO) files. A web page containing a malicious ICO file could cause
  Firefox to crash or, under certain conditions, possibly execute arbitrary
  code with the privileges of the user running Firefox. (CVE-2012-3966)

  A flaw was found in the way the 'eval' command was handled by the Firefox
  Web Console. Running 'eval' in the Web Console while viewing a web page
  containing malicious content could possibly cause Firefox to execute
  arbitrary code with the privileges of the user running Firefox.
  (CVE-2012-3980)

  An out-of-bounds memory read flaw was found in the way Firefox used the
  format-number feature of XSLT (Extensible Stylesheet Language
  Transformations). A web page containing malicious content could possibly
  cause an information leak, or cause Firefox to crash. (CVE-2012-3972)

  It was found that the SSL certificate information for a previously visited
  site could be displayed in the address bar while the main window displayed
  a new page. This could lead to phishing attacks as attackers could use this
  flaw to trick users into believing they are viewing a trusted site.
  (CVE-2012-3976)

  A flaw was found in the location object implementation in Firefox.
  Malicious content could use this flaw to possibly allow restricted content
  to be loaded. (CVE-2012-3978)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 10.0.7 ESR. You can find a link to the Mozilla
  advisories in ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~10.0.7~1.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~10.0.7~2.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~10.0.7~2.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
