###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for mailman RHSA-2015:1417-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871400");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2002-0389", "CVE-2015-2775");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-07-23 06:25:14 +0200 (Thu, 23 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for mailman RHSA-2015:1417-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mailman'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mailman is a program used to help manage e-mail discussion lists.

It was found that mailman did not sanitize the list name before passing it
to certain MTAs. A local attacker could use this flaw to execute arbitrary
code as the user running mailman. (CVE-2015-2775)

It was found that mailman stored private email messages in a world-readable
directory. A local user could use this flaw to read private mailing list
archives. (CVE-2002-0389)

This update also fixes the following bugs:

  * Previously, it was impossible to configure Mailman in a way that
Domain-based Message Authentication, Reporting &amp  Conformance (DMARC) would
recognize Sender alignment for Domain Key Identified Mail (DKIM)
signatures. Consequently, Mailman list subscribers that belonged to a mail
server with a 'reject' policy for DMARC, such as yahoo.com or AOL.com, were
unable to receive Mailman forwarded messages from senders residing in any
domain that provided DKIM signatures. With this update, domains with a
'reject' DMARC policy are recognized correctly, and Mailman list
administrators are able to configure the way these messages are handled.
As a result, after a proper configuration, subscribers now correctly
receive Mailman forwarded messages in this scenario. (BZ#1095359)

  * Mailman used a console encoding when generating a subject for a 'welcome
email' when new mailing lists were created by the 'newlist' command.
Consequently, when the console encoding did not match the encoding used by
Mailman for that particular language, characters in the 'welcome email'
could be displayed incorrectly. Mailman has been fixed to use the correct
encoding, and characters in the 'welcome email' are now displayed properly.
(BZ#1056366)

  * The 'rmlist' command used a hardcoded path to list data based on the
VAR_PREFIX configuration variable. As a consequence, when the list was
created outside of VAR_PREFIX, it was impossible to remove it using the
'rmlist' command. With this update, the 'rmlist' command uses the correct
LIST_DATA_DIR value instead of VAR_PREFIX, and it is now possible to remove
the list in described situation. (BZ#1008139)

  * Due to an incompatibility between Python and Mailman in Red Hat
Enterprise Linux 6, when moderators were approving a moderated message to a
mailing list and checked the 'Preserve messages for the site administrator'
checkbox, Mailman failed to approve the message and returned an error.
This incompatibility has been fixed, and Mailman now approves messages as
expected in this scenario. (BZ#765807)

  * When Mailman was set to no ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"mailman on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-July/msg00029.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"mailman", rpm:"mailman~2.1.12~25.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mailman-debuginfo", rpm:"mailman-debuginfo~2.1.12~25.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
