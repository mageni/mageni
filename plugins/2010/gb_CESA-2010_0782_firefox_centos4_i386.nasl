###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for firefox CESA-2010:0782 centos4 i386
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
  Runtime environment for Mozilla Firefox. Network Security Services (NSS) is
  a set of libraries designed to support the development of security-enabled
  client and server applications.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2010-3175, CVE-2010-3176, CVE-2010-3179, CVE-2010-3183,
  CVE-2010-3180)

  A flaw was found in the way the Gopher parser in Firefox converted text
  into HTML. A malformed file name on a Gopher server could, when accessed by
  a victim running Firefox, allow arbitrary JavaScript to be executed in the
  context of the Gopher domain. (CVE-2010-3177)

  A same-origin policy bypass flaw was found in Firefox. An attacker could
  create a malicious web page that, when viewed by a victim, could steal
  private data from a different website the victim has loaded with Firefox.
  (CVE-2010-3178)

  A flaw was found in the script that launches Firefox. The LD_LIBRARY_PATH
  variable was appending a &quot;.&quot; character, which could allow a local attacker
  to execute arbitrary code with the privileges of a different user running
  Firefox, if that user ran Firefox from within an attacker-controlled
  directory. (CVE-2010-3182)

  This update also provides NSS version 3.12.8 which is required by the
  updated Firefox version, fixing the following security issues:

  It was found that the SSL DHE (Diffie-Hellman Ephemeral) mode
  implementation for key exchanges in Firefox accepted DHE keys that were 256
  bits in length. This update removes support for 256 bit DHE keys, as such
  keys are easily broken using modern hardware. (CVE-2010-3173)

  A flaw was found in the way NSS matched SSL certificates when the
  certificates had a Common Name containing a wildcard and a partial IP
  address. NSS incorrectly accepted connections to IP addresses that fell
  within the SSL certificate's wildcard range as valid SSL connections,
  possibly allowing an attacker to conduct a man-in-the-middle attack.
  (CVE-2010-3170)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 3.6.11. You can find a link to the Mozilla
  advisories in the References section of this erratum.

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 3.6.11, which corrects these issues. After installing the
  update, Firefox must be restarted for the changes to take effect.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "firefox on CentOS 4";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-October/017113.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313559");
  script_version("$Revision: 8269 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-02 08:28:22 +0100 (Tue, 02 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-04 12:09:38 +0100 (Thu, 04 Nov 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-3170", "CVE-2010-3173", "CVE-2010-3175", "CVE-2010-3176", "CVE-2010-3177", "CVE-2010-3178", "CVE-2010-3179", "CVE-2010-3180", "CVE-2010-3182", "CVE-2010-3183");
  script_name("CentOS Update for firefox CESA-2010:0782 centos4 i386");

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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.6.11~2.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.12.8~1.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.12.8~1.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.12.8~1.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
