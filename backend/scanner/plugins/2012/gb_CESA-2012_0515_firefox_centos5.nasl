###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for firefox CESA-2012:0515 centos5
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-April/018593.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881202");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:42:34 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-3062", "CVE-2012-0467", "CVE-2012-0468", "CVE-2012-0469",
                "CVE-2012-0470", "CVE-2012-0471", "CVE-2012-0472", "CVE-2012-0473",
                "CVE-2012-0474", "CVE-2012-0477", "CVE-2012-0478", "CVE-2012-0479");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for firefox CESA-2012:0515 centos5");

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

  A flaw was found in Sanitiser for OpenType (OTS), used by Firefox to help
  prevent potential exploits in malformed OpenType fonts. A web page
  containing malicious content could cause Firefox to crash or, under certain
  conditions, possibly execute arbitrary code with the privileges of the user
  running Firefox. (CVE-2011-3062)

  A web page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2012-0467, CVE-2012-0468, CVE-2012-0469)

  A web page containing a malicious Scalable Vector Graphics (SVG) image file
  could cause Firefox to crash or, potentially, execute arbitrary code with
  the privileges of the user running Firefox. (CVE-2012-0470)

  A flaw was found in the way Firefox used its embedded Cairo library to
  render certain fonts. A web page containing malicious content could cause
  Firefox to crash or, under certain conditions, possibly execute arbitrary
  code with the privileges of the user running Firefox. (CVE-2012-0472)

  A flaw was found in the way Firefox rendered certain images using WebGL. A
  web page containing malicious content could cause Firefox to crash or,
  under certain conditions, possibly execute arbitrary code with the
  privileges of the user running Firefox. (CVE-2012-0478)

  A cross-site scripting (XSS) flaw was found in the way Firefox handled
  certain multibyte character sets. A web page containing malicious content
  could cause Firefox to run JavaScript code with the permissions of a
  different website. (CVE-2012-0471)

  A flaw was found in the way Firefox rendered certain graphics using WebGL.
  A web page containing malicious content could cause Firefox to crash.
  (CVE-2012-0473)

  A flaw in Firefox allowed the address bar to display a different website
  than the one the user was visiting. An attacker could use this flaw to
  conceal a malicious URL, possibly tricking a user into believing they are
  viewing a trusted site, or allowing scripts to be loaded from the
  attacker's site, possibly leading to cross-site scripting (XSS) attacks.
  (CVE-2012-0474)

  A flaw was found in the way Firefox decoded the ISO-2022-KR and ISO-2022-CN
  character sets. A web page containing malicious content could cause Firefox
  to run JavaScript code with the permissions of a different website.
  (CVE-2012-0477)

  A flaw was found in the way Firefox handled RSS and Atom feeds. Invalid
  RSS or Atom content loaded ov ...

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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~10.0.4~1.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~10.0.4~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~10.0.4~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
