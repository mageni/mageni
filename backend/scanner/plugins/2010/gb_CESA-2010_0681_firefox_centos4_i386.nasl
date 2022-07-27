###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for firefox CESA-2010:0681 centos4 i386
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
tag_insight = "Mozilla Firefox is an open source web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2010-3169, CVE-2010-2762)

  Several use-after-free and dangling pointer flaws were found in Firefox. A
  web page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2010-2760, CVE-2010-2766, CVE-2010-2767, CVE-2010-3167,
  CVE-2010-3168)

  Multiple buffer overflow flaws were found in Firefox. A web page containing
  malicious content could cause Firefox to crash or, potentially, execute
  arbitrary code with the privileges of the user running Firefox.
  (CVE-2010-2765, CVE-2010-3166)

  Multiple cross-site scripting (XSS) flaws were found in Firefox. A web page
  containing malicious content could cause Firefox to run JavaScript code
  with the permissions of a different website. (CVE-2010-2768, CVE-2010-2769)

  A flaw was found in the Firefox XMLHttpRequest object. A remote site could
  use this flaw to gather information about servers on an internal private
  network. (CVE-2010-2764)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 3.6.9. You can find a link to the Mozilla advisories
  in the References section of this erratum.

  Note: After installing this update, Firefox will fail to connect (with
  HTTPS) to a server using the SSL DHE (Diffie-Hellman Ephemeral) key
  exchange if the server's ephemeral key is too small. Connecting to such
  servers is a security risk as an ephemeral key that is too small makes the
  SSL connection vulnerable to attack. Refer to the Solution section for
  further information.

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 3.6.9, which corrects these issues. After installing the
  update, Firefox must be restarted for the changes to take effect.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "firefox on CentOS 4";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-September/016968.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314758");
  script_version("$Revision: 8254 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-28 08:29:05 +0100 (Thu, 28 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-09-10 14:21:00 +0200 (Fri, 10 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2760", "CVE-2010-2762", "CVE-2010-2764", "CVE-2010-2765", "CVE-2010-2766", "CVE-2010-2767", "CVE-2010-2768", "CVE-2010-2769", "CVE-2010-3166", "CVE-2010-3167", "CVE-2010-3168", "CVE-2010-3169");
  script_name("CentOS Update for firefox CESA-2010:0681 centos4 i386");

  script_tag(name: "summary" , value: "Check for the Version of firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.6.9~1.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.8.6~1.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.8.6~1.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.12.7~1.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.12.7~1.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.12.7~1.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
