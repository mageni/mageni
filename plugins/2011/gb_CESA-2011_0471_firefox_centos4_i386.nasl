###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for firefox CESA-2011:0471 centos4 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-April/017470.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880561");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0067", "CVE-2011-0069", "CVE-2011-0070",
                "CVE-2011-0071", "CVE-2011-0072", "CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075",
                "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080", "CVE-2011-0081", "CVE-2011-1202");
  script_name("CentOS Update for firefox CESA-2011:0471 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"firefox on CentOS 4");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could possibly lead to arbitrary code
  execution with the privileges of the user running Firefox. (CVE-2011-0080,
  CVE-2011-0081)

  An arbitrary memory write flaw was found in the way Firefox handled
  out-of-memory conditions. If all memory was consumed when a user visited a
  malicious web page, it could possibly lead to arbitrary code execution
  with the privileges of the user running Firefox. (CVE-2011-0078)

  An integer overflow flaw was found in the way Firefox handled the HTML
  frameset tag. A web page with a frameset tag containing large values for
  the 'rows' and 'cols' attributes could trigger this flaw, possibly leading
  to arbitrary code execution with the privileges of the user running
  Firefox. (CVE-2011-0077)

  A flaw was found in the way Firefox handled the HTML iframe tag. A web page
  with an iframe tag containing a specially-crafted source address could
  trigger this flaw, possibly leading to arbitrary code execution with the
  privileges of the user running Firefox. (CVE-2011-0075)

  A flaw was found in the way Firefox displayed multiple marquee elements. A
  malformed HTML document could cause Firefox to execute arbitrary code with
  the privileges of the user running Firefox. (CVE-2011-0074)

  A flaw was found in the way Firefox handled the nsTreeSelection element.
  Malformed content could cause Firefox to execute arbitrary code with the
  privileges of the user running Firefox. (CVE-2011-0073)

  A use-after-free flaw was found in the way Firefox appended frame and
  iframe elements to a DOM tree when the NoScript add-on was enabled.
  Malicious HTML content could cause Firefox to execute arbitrary code with
  the privileges of the user running Firefox. (CVE-2011-0072)

  A directory traversal flaw was found in the Firefox resource:// protocol
  handler. Malicious content could cause Firefox to access arbitrary files
  accessible to the user running Firefox. (CVE-2011-0071)

  A double free flaw was found in the way Firefox handled
  'application/http-index-format' documents. A malformed HTTP response could
  cause Firefox to execute arbitrary code with the privileges of the user
  running Firefox. (CVE-2011-0070)

  A flaw was found in the way Firefox handled certain JavaScript cross-domain
  requests. If malicious content generated a large number of cross-domain
  JavaScript reque ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.6.17~2.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
