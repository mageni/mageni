###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for squirrelmail RHSA-2013:0126-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-January/msg00009.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870880");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-01-11 16:42:08 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2012-2124", "CVE-2010-2813");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for squirrelmail RHSA-2013:0126-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squirrelmail'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"squirrelmail on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"SquirrelMail is a standards-based webmail package written in PHP.

  The SquirrelMail security update RHSA-2012:0103 did not, unlike the erratum
  text stated, correct the CVE-2010-2813 issue, a flaw in the way
  SquirrelMail handled failed log in attempts. A user preference file was
  created when attempting to log in with a password containing an 8-bit
  character, even if the username was not valid. A remote attacker could use
  this flaw to eventually consume all hard disk space on the target
  SquirrelMail server. (CVE-2012-2124)

  This update also fixes the following bugs:

  * Prior to this update, SquirrelMail could not decode multi-line subjects
  properly. Consequently, the decode header internationalization option did
  not properly handle new lines or tabs at the beginning of the lines. This
  bug has been fixed and SquirrelMail now works correctly in the described
  scenario. (BZ#241861)

  * Due to a bug, attachments written in HTML code on the Windows operating
  system were not displayed properly when accessed with SquirrelMail. The
  '!=null' string was trimmed to '!ull'. This bug has been fixed and the
  attachments are now displayed correctly in such a case. (BZ#359791)

  * Previously, e-mail messages with a Unique Identifier (UID) larger than
  2^31 bytes were unreadable when using the squirrelmail package. With this
  patch the squirrelmail package is able to read all messages regardless of
  the UIDs size. (BZ#450780)

  * Due to a bug, a PHP script did not assign the proper character set to
  requested variables. Consequently, SquirrelMail could not display any
  e-mails. The underlying source code has been modified and now the
  squirrelmail package assigns the correct character set. (BZ#475188)

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.8~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
