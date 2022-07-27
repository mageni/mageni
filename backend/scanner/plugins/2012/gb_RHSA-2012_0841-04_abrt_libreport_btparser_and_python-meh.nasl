###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for abrt, libreport, btparser, and python-meh RHSA-2012:0841-04
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-June/msg00028.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870768");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-06-22 10:26:13 +0530 (Fri, 22 Jun 2012)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2011-4088", "CVE-2012-1106");
  script_name("RedHat Update for abrt, libreport, btparser, and python-meh RHSA-2012:0841-04");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'abrt, libreport, btparser, and python-meh'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"abrt, libreport, btparser, and python-meh on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"ABRT (Automatic Bug Reporting Tool) is a tool to help users to detect
  defects in applications and to create a bug report with all the information
  needed by a maintainer to fix it. It uses a plug-in system to extend its
  functionality. libreport provides an API for reporting different problems
  in applications to different bug targets, such as Bugzilla, FTP, and Trac.

  The btparser utility is a backtrace parser and analyzer library, which
  works with backtraces produced by the GNU Project Debugger. It can parse a
  text file with a backtrace to a tree of C structures, allowing to analyze
  the threads and frames of the backtrace and process them.

  The python-meh package provides a python library for handling exceptions.

  If the C handler plug-in in ABRT was enabled (the abrt-addon-ccpp package
  installed and the abrt-ccpp service running), and the sysctl
  fs.suid_dumpable option was set to '2' (it is '0' by default), core dumps
  of set user ID (setuid) programs were created with insecure group ID
  permissions. This could allow local, unprivileged users to obtain sensitive
  information from the core dump files of setuid processes they would
  otherwise not be able to access. (CVE-2012-1106)

  ABRT did not allow users to easily search the collected crash information
  for sensitive data prior to submitting it. This could lead to users
  unintentionally exposing sensitive information via the submitted crash
  reports. This update adds functionality to search across all the collected
  data. Note that this fix does not apply to the default configuration, where
  reports are sent to Red Hat Customer Support. It only takes effect for
  users sending information to Red Hat Bugzilla. (CVE-2011-4088)

  Red Hat would like to thank Jan Iven for reporting CVE-2011-4088.

  These updated packages include numerous bug fixes. Space precludes
  documenting all of these changes in this advisory. Users are directed to
  the Red Hat Enterprise Linux 6.3 Technical Notes for information on the
  most significant of these changes.

  All users of abrt, libreport, btparser, and python-meh are advised to
  upgrade to these updated packages, which correct these issues.");
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

  if ((res = isrpmvuln(pkg:"btparser", rpm:"btparser~0.16~3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"btparser-debuginfo", rpm:"btparser-debuginfo~0.16~3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport", rpm:"libreport~2.0.9~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-cli", rpm:"libreport-cli~2.0.9~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-debuginfo", rpm:"libreport-debuginfo~2.0.9~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-gtk", rpm:"libreport-gtk~2.0.9~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-newt", rpm:"libreport-newt~2.0.9~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-kerneloops", rpm:"libreport-plugin-kerneloops~2.0.9~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-logger", rpm:"libreport-plugin-logger~2.0.9~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-mailx", rpm:"libreport-plugin-mailx~2.0.9~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-reportuploader", rpm:"libreport-plugin-reportuploader~2.0.9~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-rhtsupport", rpm:"libreport-plugin-rhtsupport~2.0.9~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-python", rpm:"libreport-python~2.0.9~5.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-meh", rpm:"python-meh~0.12.1~3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
