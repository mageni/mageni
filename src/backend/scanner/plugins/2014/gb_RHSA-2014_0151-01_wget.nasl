###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for wget RHSA-2014:0151-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871122");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-02-11 10:51:02 +0530 (Tue, 11 Feb 2014)");
  script_cve_id("CVE-2010-2252");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for wget RHSA-2014:0151-01");


  script_tag(name:"affected", value:"wget on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"The wget package provides the GNU Wget file retrieval utility for HTTP,
HTTPS, and FTP protocols. Wget provides various useful features, such as
the ability to work in the background while the user is logged out,
recursive retrieval of directories, file name wildcard matching or updating
files in dependency on file timestamp comparison.

It was discovered that wget used a file name provided by the server when
saving a downloaded file. This could cause wget to create a file with a
different name than expected, possibly allowing the server to execute
arbitrary code on the client. (CVE-2010-2252)

Note: With this update, wget always uses the last component of the original
URL as the name for the downloaded file. Previous behavior of using the
server provided name or the last component of the redirected URL when
creating files can be re-enabled by using the '--trust-server-names'
command line option, or by setting 'trust_server_names=on' in the wget
start-up file.

This update also fixes the following bugs:

  * Prior to this update, the wget package did not recognize HTTPS SSL
certificates with alternative names (subjectAltName) specified in the
certificate as valid. As a consequence, running the wget command failed
with a certificate error. This update fixes wget to recognize such
certificates as valid. (BZ#1060113)

All users of wget are advised to upgrade to this updated package, which
contain backported patches to correct these issues.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-February/msg00014.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'wget'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"wget", rpm:"wget~1.12~1.11.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wget-debuginfo", rpm:"wget-debuginfo~1.12~1.11.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
