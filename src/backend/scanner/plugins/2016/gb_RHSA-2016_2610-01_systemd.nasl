###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for systemd RHSA-2016:2610-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871703");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-04 05:42:44 +0100 (Fri, 04 Nov 2016)");
  script_cve_id("CVE-2016-7795");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for systemd RHSA-2016:2610-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The systemd packages contain systemd,
a system and service manager for Linux, compatible with the SysV and LSB
init scripts. It provides aggressive parallelism capabilities, uses socket
and D-Bus activation for starting services, offers on-demand starting of daemons,
and keeps track of processes using Linux cgroups. In addition, it supports
snapshotting and restoring of the system state, maintains mount and automount
points, and implements an elaborate transactional dependency-based service control
logic. It can also work as a drop-in replacement for sysvinit.

Security Fix(es):

  * A flaw was found in the way systemd handled empty notification messages.
A local attacker could use this flaw to make systemd freeze its execution,
preventing further management of system services, system shutdown, or
zombie process collection via systemd. (CVE-2016-7795)

Bug Fix(es):

  * Previously, the udev device manager automatically enabled all memory
banks on IBM z System installations. As a consequence, hot plug memory was
enabled automatically, which was incorrect. With this update, system
architecture checks have been added to the udev rules to address the
problem. As a result, hot plug memory is no longer automatically enabled.
(BZ#1381123)");
  script_tag(name:"affected", value:"systemd on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-November/msg00044.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"libgudev1-219-30.el7", rpm:"libgudev1-219-30.el7~3.3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgudev1-devel-219-30.el7", rpm:"libgudev1-devel-219-30.el7~3.3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-219-30.el7", rpm:"systemd-219-30.el7~3.3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-debuginfo-219-30.el7", rpm:"systemd-debuginfo-219-30.el7~3.3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-devel-219-30.el7", rpm:"systemd-devel-219-30.el7~3.3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-libs-219-30.el7", rpm:"systemd-libs-219-30.el7~3.3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-python-219-30.el7", rpm:"systemd-python-219-30.el7~3.3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-sysv-219-30.el7", rpm:"systemd-sysv-219-30.el7~3.3", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
