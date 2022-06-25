###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for postfix CESA-2011:0422 centos5 x86_64
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-April/017292.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881389");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:40:12 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2008-2937", "CVE-2011-0411");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for postfix CESA-2011:0422 centos5 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postfix'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"postfix on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Postfix is a Mail Transport Agent (MTA), supporting LDAP, SMTP AUTH (SASL),
  and TLS.

  It was discovered that Postfix did not flush the received SMTP commands
  buffer after switching to TLS encryption for an SMTP session. A
  man-in-the-middle attacker could use this flaw to inject SMTP commands into
  a victim's session during the plain text phase. This would lead to those
  commands being processed by Postfix after TLS encryption is enabled,
  possibly allowing the attacker to steal the victim's mail or authentication
  credentials. (CVE-2011-0411)

  It was discovered that Postfix did not properly check the permissions of
  users' mailbox files. A local attacker able to create files in the mail
  spool directory could use this flaw to create mailbox files for other local
  users, and be able to read mail delivered to those users. (CVE-2008-2937)

  Red Hat would like to thank the CERT/CC for reporting CVE-2011-0411, and
  Sebastian Krahmer of the SuSE Security Team for reporting CVE-2008-2937.
  The CERT/CC acknowledges Wietse Venema as the original reporter of
  CVE-2011-0411.

  Users of Postfix are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. After installing this
  update, the postfix service will be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.3.3~2.2.el5_6", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-pflogsumm", rpm:"postfix-pflogsumm~2.3.3~2.2.el5_6", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
