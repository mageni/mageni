###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for evolution CESA-2013:0516 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019304.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881642");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-12 09:59:23 +0530 (Tue, 12 Mar 2013)");
  script_cve_id("CVE-2011-3201");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("CentOS Update for evolution CESA-2013:0516 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'evolution'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"evolution on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Evolution is the GNOME mailer, calendar, contact manager and communication
  tool. The components which make up Evolution are tightly integrated with
  one another and act as a seamless personal information-management tool.

  The way Evolution handled mailto URLs allowed any file to be attached to
  the new message. This could lead to information disclosure if the user did
  not notice the attached file before sending the message. With this update,
  mailto URLs cannot be used to attach certain files, such as hidden files or
  files in hidden directories, files in the /etc/ directory, or files
  specified using a path containing '..'. (CVE-2011-3201)

  Red Hat would like to thank Matt McCutchen for reporting this issue.

  This update also fixes the following bugs:

  * Creating a contact list with contact names encoded in UTF-8 caused these
  names to be displayed in the contact list editor in the ASCII encoding
  instead of UTF-8. This bug has been fixed and the contact list editor now
  displays the names in the correct format. (BZ#707526)

  * Due to a bug in the evolution-alarm-notify process, calendar appointment
  alarms did not appear in some types of calendars. The underlying source
  code has been modified and calendar notifications work as expected.
  (BZ#805239)

  * An attempt to print a calendar month view as a PDF file caused Evolution
  to terminate unexpectedly. This update applies a patch to fix this bug and
  Evolution no longer crashes in this situation. (BZ#890642)

  All evolution users are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. All running instances
  of Evolution must be restarted for this update to take effect.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.28.3~30.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-conduits", rpm:"evolution-conduits~2.28.3~30.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.28.3~30.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-help", rpm:"evolution-help~2.28.3~30.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-perl", rpm:"evolution-perl~2.28.3~30.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-pst", rpm:"evolution-pst~2.28.3~30.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution-spamassassin", rpm:"evolution-spamassassin~2.28.3~30.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
