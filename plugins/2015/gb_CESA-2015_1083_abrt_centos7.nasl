###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for abrt CESA-2015:1083 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882200");
  script_version("$Revision: 14058 $");
  script_cve_id("CVE-2015-1869", "CVE-2015-1870", "CVE-2015-3142", "CVE-2015-3147",
                "CVE-2015-3150", "CVE-2015-3151", "CVE-2015-3159", "CVE-2015-3315");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-06-16 06:14:05 +0200 (Tue, 16 Jun 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for abrt CESA-2015:1083 centos7");
  script_tag(name:"summary", value:"Check the version of abrt");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"ABRT (Automatic Bug Reporting Tool) is a tool
  to help users to detect
defects in applications and to create a bug report with all the information
needed by a maintainer to fix it. It uses a plug-in system to extend its
functionality.

It was found that ABRT was vulnerable to multiple race condition and
symbolic link flaws. A local attacker could use these flaws to potentially
escalate their privileges on the system. (CVE-2015-3315)

It was discovered that the kernel-invoked coredump processor provided by
ABRT wrote core dumps to files owned by other system users. This could
result in information disclosure if an application crashed while its
current directory was a directory writable to by other users (such as
/tmp). (CVE-2015-3142)

It was discovered that the default event handling scripts installed by ABRT
did not handle symbolic links correctly. A local attacker with write access
to an ABRT problem directory could use this flaw to escalate their
privileges. (CVE-2015-1869)

It was found that the ABRT event scripts created a user-readable copy of an
sosreport file in ABRT problem directories, and included excerpts of
/var/log/messages selected by the user-controlled process name, leading to
an information disclosure. (CVE-2015-1870)

It was discovered that, when moving problem reports between certain
directories, abrt-handle-upload did not verify that the new problem
directory had appropriate permissions and did not contain symbolic links.
An attacker able to create a crafted problem report could use this flaw to
expose other parts of ABRT to attack, or to overwrite arbitrary files on
the system. (CVE-2015-3147)

Multiple directory traversal flaws were found in the abrt-dbus D-Bus
service. A local attacker could use these flaws to read and write arbitrary
files as the root user. (CVE-2015-3151)

It was discovered that the abrt-dbus D-Bus service did not properly check
the validity of the problem directory argument in the ChownProblemDir,
DeleteElement, and DeleteProblem methods. A local attacker could use this
flaw to take ownership of arbitrary files and directories, or to delete
files and directories as the root user. (CVE-2015-3150)

It was discovered that the abrt-action-install-debuginfo-to-abrt-cache
helper program did not properly filter the process environment before
invoking abrt-action-install-debuginfo. A local attacker could use this
flaw to escalate their privileges on the system. (CVE-2015-3159)

All users of abrt are advised to upgrade to these updated packages, which
correct these issues.");
  script_tag(name:"affected", value:"abrt on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-June/021170.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"abrt", rpm:"abrt~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-addon-ccpp", rpm:"abrt-addon-ccpp~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-addon-kerneloops", rpm:"abrt-addon-kerneloops~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-addon-pstoreoops", rpm:"abrt-addon-pstoreoops~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-addon-python", rpm:"abrt-addon-python~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-addon-upload-watch", rpm:"abrt-addon-upload-watch~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-addon-vmcore", rpm:"abrt-addon-vmcore~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-addon-xorg", rpm:"abrt-addon-xorg~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-cli", rpm:"abrt-cli~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-console-notification", rpm:"abrt-console-notification~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-dbus", rpm:"abrt-dbus~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-desktop", rpm:"abrt-desktop~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-devel", rpm:"abrt-devel~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-gui", rpm:"abrt-gui~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-gui-devel", rpm:"abrt-gui-devel~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-gui-libs", rpm:"abrt-gui-libs~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-libs", rpm:"abrt-libs~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-python", rpm:"abrt-python~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-python-doc", rpm:"abrt-python-doc~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-retrace-client", rpm:"abrt-retrace-client~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"abrt-tui", rpm:"abrt-tui~2.1.11~22.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport", rpm:"libreport~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-anaconda", rpm:"libreport-anaconda~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-centos", rpm:"libreport-centos~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-cli", rpm:"libreport-cli~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-compat", rpm:"libreport-compat~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-devel", rpm:"libreport-devel~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-filesystem", rpm:"libreport-filesystem~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-gtk", rpm:"libreport-gtk~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-gtk-devel", rpm:"libreport-gtk-devel~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-newt", rpm:"libreport-newt~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-bugzilla", rpm:"libreport-plugin-bugzilla~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-kerneloops", rpm:"libreport-plugin-kerneloops~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-logger", rpm:"libreport-plugin-logger~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-mailx", rpm:"libreport-plugin-mailx~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-mantisbt", rpm:"libreport-plugin-mantisbt~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-reportuploader", rpm:"libreport-plugin-reportuploader~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-rhtsupport", rpm:"libreport-plugin-rhtsupport~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-ureport", rpm:"libreport-plugin-ureport~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-python", rpm:"libreport-python~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-rhel", rpm:"libreport-rhel~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-rhel-anaconda-bugzilla", rpm:"libreport-rhel-anaconda-bugzilla~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-rhel-bugzilla", rpm:"libreport-rhel-bugzilla~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-web", rpm:"libreport-web~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-web-devel", rpm:"libreport-web-devel~2.1.11~23.el7.centos.0.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
