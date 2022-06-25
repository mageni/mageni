###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for mailman RHSA-2015:1153-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871378");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-06-24 06:12:54 +0200 (Wed, 24 Jun 2015)");
  script_cve_id("CVE-2015-2775");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for mailman RHSA-2015:1153-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mailman'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mailman is a program used to help manage email discussion lists.

It was found that mailman did not sanitize the list name before passing it
to certain MTAs. A local attacker could use this flaw to execute arbitrary
code as the user running mailman. (CVE-2015-2775)

This update also fixes the following bugs:

  * Previously, it was impossible to configure Mailman in a way that
Domain-based Message Authentication, Reporting &amp  Conformance (DMARC) would
recognize Sender alignment for Domain Key Identified Mail (DKIM)
signatures. Consequently, Mailman list subscribers that belonged to a mail
server with a 'reject' policy for DMARC, such as yahoo.com or AOL.com, were
unable to receive Mailman forwarded messages from senders residing in any
domain that provided DKIM signatures. With this update, domains with a
'reject' DMARC policy are recognized correctly, and Mailman list
administrators are able to configure the way these messages are handled. As
a result, after a proper configuration, subscribers now correctly receive
Mailman forwarded messages in this scenario. (BZ#1229288)

  * Previously, the /etc/mailman file had incorrectly set permissions, which
in some cases caused removing Mailman lists to fail with a ''NoneType'
object has no attribute 'close'' message. With this update, the permissions
value for /etc/mailman is correctly set to 2775 instead of 0755, and
removing Mailman lists now works as expected. (BZ#1229307)

  * Prior to this update, the mailman utility incorrectly installed the
tmpfiles configuration in the /etc/tmpfiles.d/ directory. As a consequence,
changes made to mailman tmpfiles configuration were overwritten if the
mailman packages were reinstalled or updated. The mailman utility now
installs the tmpfiles configuration in the /usr/lib/tmpfiles.d/ directory,
and changes made to them by the user are preserved on reinstall or update.
(BZ#1229306)

All mailman users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.");
  script_tag(name:"affected", value:"mailman on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-June/msg00027.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"mailman", rpm:"mailman~2.1.15~21.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mailman-debuginfo", rpm:"mailman-debuginfo~2.1.15~21.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
