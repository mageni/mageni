###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for firefox CESA-2012:1350 centos5
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-October/018928.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881512");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-10-11 10:02:01 +0530 (Thu, 11 Oct 2012)");
  script_cve_id("CVE-2012-1956", "CVE-2012-3982", "CVE-2012-3986", "CVE-2012-3988",
                "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-3992", "CVE-2012-3993",
                "CVE-2012-3994", "CVE-2012-3995", "CVE-2012-4179", "CVE-2012-4180",
                "CVE-2012-4181", "CVE-2012-4182", "CVE-2012-4183", "CVE-2012-4184",
                "CVE-2012-4185", "CVE-2012-4186", "CVE-2012-4187", "CVE-2012-4188");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for firefox CESA-2012:1350 centos5");

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

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2012-3982, CVE-2012-3988, CVE-2012-3990, CVE-2012-3995,
  CVE-2012-4179, CVE-2012-4180, CVE-2012-4181, CVE-2012-4182, CVE-2012-4183,
  CVE-2012-4185, CVE-2012-4186, CVE-2012-4187, CVE-2012-4188)

  Two flaws in Firefox could allow a malicious website to bypass intended
  restrictions, possibly leading to information disclosure, or Firefox
  executing arbitrary code. Note that the information disclosure issue could
  possibly be combined with other flaws to achieve arbitrary code execution.
  (CVE-2012-3986, CVE-2012-3991)

  Multiple flaws were found in the location object implementation in Firefox.
  Malicious content could be used to perform cross-site scripting attacks,
  script injection, or spoofing attacks. (CVE-2012-1956, CVE-2012-3992,
  CVE-2012-3994)

  Two flaws were found in the way Chrome Object Wrappers were implemented.
  Malicious content could be used to perform cross-site scripting attacks or
  cause Firefox to execute arbitrary code. (CVE-2012-3993, CVE-2012-4184)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 10.0.8 ESR. You can find a link to the Mozilla
  advisories in the References section of this erratum.

  Red Hat would like to thank the Mozilla project for reporting these issues.
  Upstream acknowledges Christian Holler, Jesse Ruderman, Soroush Dalili,
  miaubiz, Abhishek Arya, Atte Kettunen, Johnny Stenback, Alice White,
  moz_bug_r_a4, and Mariusz Mlynski as the original reporters of these
  issues.

  This update also fixes the following bug:

  * In certain environments, storing personal Firefox configuration files
  (~/.mozilla/) on an NFS share, such as when your home directory is on a
  NFS share, led to Firefox functioning incorrectly, for example, navigation
  buttons not working as expected, and bookmarks not saving. This update
  adds a new configuration option, storage.nfs_filesystem, that can be used
  to resolve this issue.

  If you experience this issue:

  1) Start Firefox.

  2) Type 'about:config' (without quotes) into the URL bar and press the
  Enter key.

  3) If prompted with 'This might void your warranty!', click the 'I'll be
  careful, I promise!' button.

  4) Right-click in the  ...

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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~10.0.8~1.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~10.0.8~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~10.0.8~1.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
