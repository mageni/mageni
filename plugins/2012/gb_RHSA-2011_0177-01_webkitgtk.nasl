###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for webkitgtk RHSA-2011:0177-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-January/msg00022.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870727");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-06-05 19:33:18 +0530 (Tue, 05 Jun 2012)");
  script_cve_id("CVE-2010-1780", "CVE-2010-1782", "CVE-2010-1783", "CVE-2010-1784",
                "CVE-2010-1785", "CVE-2010-1786", "CVE-2010-1787", "CVE-2010-1788",
                "CVE-2010-1790", "CVE-2010-1792", "CVE-2010-1793", "CVE-2010-1807",
                "CVE-2010-1812", "CVE-2010-1814", "CVE-2010-1815", "CVE-2010-3113",
                "CVE-2010-3114", "CVE-2010-3115", "CVE-2010-3116", "CVE-2010-3119",
                "CVE-2010-3255", "CVE-2010-3257", "CVE-2010-3259", "CVE-2010-3812",
                "CVE-2010-3813", "CVE-2010-4197", "CVE-2010-4198", "CVE-2010-4204",
                "CVE-2010-4206", "CVE-2010-4577");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for webkitgtk RHSA-2011:0177-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkitgtk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"webkitgtk on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"WebKitGTK+ is the port of the portable web rendering engine WebKit to the
  GTK+ platform.

  Multiple memory corruption flaws were found in WebKit. Malicious web
  content could cause an application using WebKitGTK+ to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  the application. (CVE-2010-1782, CVE-2010-1783, CVE-2010-1784,
  CVE-2010-1785, CVE-2010-1787, CVE-2010-1788, CVE-2010-1790, CVE-2010-1792,
  CVE-2010-1807, CVE-2010-1814, CVE-2010-3114, CVE-2010-3116, CVE-2010-3119,
  CVE-2010-3255, CVE-2010-3812, CVE-2010-4198)

  Multiple use-after-free flaws were found in WebKit. Malicious web content
  could cause an application using WebKitGTK+ to crash or, potentially,
  execute arbitrary code with the privileges of the user running the
  application. (CVE-2010-1780, CVE-2010-1786, CVE-2010-1793, CVE-2010-1812,
  CVE-2010-1815, CVE-2010-3113, CVE-2010-3257, CVE-2010-4197, CVE-2010-4204)

  Two array index errors, leading to out-of-bounds memory reads, were found
  in WebKit. Malicious web content could cause an application using
  WebKitGTK+ to crash. (CVE-2010-4206, CVE-2010-4577)

  A flaw in WebKit could allow malicious web content to trick a user into
  thinking they are visiting the site reported by the location bar, when the
  page is actually content controlled by an attacker. (CVE-2010-3115)

  It was found that WebKit did not correctly restrict read access to images
  created from the 'canvas' element. Malicious web content could allow a
  remote attacker to bypass the same-origin policy and potentially access
  sensitive image data. (CVE-2010-3259)

  A flaw was found in the way WebKit handled DNS prefetching. Even when it
  was disabled, web content containing certain 'link' elements could cause
  WebKitGTK+ to perform DNS prefetching. (CVE-2010-3813)

  Users of WebKitGTK+ should upgrade to these updated packages, which contain
  WebKitGTK+ version 1.2.6, and resolve these issues. All running
  applications that use WebKitGTK+ must be restarted for this update to take
  effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"webkitgtk", rpm:"webkitgtk~1.2.6~2.el6_0", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkitgtk-debuginfo", rpm:"webkitgtk-debuginfo~1.2.6~2.el6_0", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
