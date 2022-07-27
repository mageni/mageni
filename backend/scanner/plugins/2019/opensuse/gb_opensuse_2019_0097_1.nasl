###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for systemd openSUSE-SU-2019:0097-1 (systemd)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852259");
  script_version("2019-05-10T14:24:23+0000");
  script_cve_id("CVE-2018-16864", "CVE-2018-16865", "CVE-2018-16866");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-10 14:24:23 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2019-01-30 04:03:12 +0100 (Wed, 30 Jan 2019)");
  script_name("SuSE Update for systemd openSUSE-SU-2019:0097-1 (systemd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-01/msg00040.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the openSUSE-SU-2019:0097_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd provides the following fixes:

  Security issues fixed:

  - CVE-2018-16864, CVE-2018-16865: Fixed two memory corruptions through
  attacker-controlled alloca()s (bsc#1120323)

  - CVE-2018-16866: Fixed an information leak in journald (bsc#1120323)

  - Fixed an issue during system startup in relation to encrypted swap disks
  (bsc#1119971)

  Non-security issues fixed:

  - core: Queue loading transient units after setting their properties.
  (bsc#1115518)

  - logind: Stop managing VT switches if no sessions are registered on that
  VT. (bsc#1101591)

  - terminal-util: introduce vt_release() and vt_restore() helpers.

  - terminal: Unify code for resetting kbd utf8 mode a bit.

  - terminal Reset should honour default_utf8 kernel setting.

  - logind: Make session_restore_vt() static.

  - udev: Downgrade message when setting inotify watch up fails.
  (bsc#1005023)

  - log: Never log into foreign fd #2 in PID 1 or its pre-execve() children.
  (bsc#1114981)

  - udev: Ignore the exit code of systemd-detect-virt for memory hot-add.
  In SLE-12-SP3, 80-hotplug-cpu-mem.rules has a memory hot-add rule that
  uses systemd-detect-virt to detect non-zvm environment. The
  systemd-detect-virt returns exit failure code when it detected _none_
  state.  The exit failure code causes that the hot-add memory block can
  not be set to online. (bsc#1076696)

  This update was imported from the SUSE:SLE-12-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-97=1");

  script_tag(name:"affected", value:"systemd on openSUSE Leap 42.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"libsystemd0-228", rpm:"libsystemd0-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0-debuginfo-228", rpm:"libsystemd0-debuginfo-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0-mini-228", rpm:"libsystemd0-mini-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0-mini-debuginfo-228", rpm:"libsystemd0-mini-debuginfo-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-devel-228", rpm:"libudev-devel-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-mini-devel-228", rpm:"libudev-mini-devel-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-mini1-228", rpm:"libudev-mini1-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-mini1-debuginfo-228", rpm:"libudev-mini1-debuginfo-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1-228", rpm:"libudev1-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1-debuginfo-228", rpm:"libudev1-debuginfo-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname-228", rpm:"nss-myhostname-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname-debuginfo-228", rpm:"nss-myhostname-debuginfo-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-mymachines-228", rpm:"nss-mymachines-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-mymachines-debuginfo-228", rpm:"nss-mymachines-debuginfo-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-228", rpm:"systemd-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-debuginfo-228", rpm:"systemd-debuginfo-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-debugsource-228", rpm:"systemd-debugsource-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-devel-228", rpm:"systemd-devel-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-logger-228", rpm:"systemd-logger-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-228", rpm:"systemd-mini-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-debuginfo-228", rpm:"systemd-mini-debuginfo-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-debugsource-228", rpm:"systemd-mini-debugsource-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-devel-228", rpm:"systemd-mini-devel-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-sysvinit-228", rpm:"systemd-mini-sysvinit-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-sysvinit-228", rpm:"systemd-sysvinit-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-228", rpm:"udev-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-debuginfo-228", rpm:"udev-debuginfo-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-mini-228", rpm:"udev-mini-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-mini-debuginfo-228", rpm:"udev-mini-debuginfo-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-bash-completion-228", rpm:"systemd-bash-completion-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-bash-completion-228", rpm:"systemd-mini-bash-completion-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0-32bit-228", rpm:"libsystemd0-32bit-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0-debuginfo-32bit-228", rpm:"libsystemd0-debuginfo-32bit-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1-32bit-228", rpm:"libudev1-32bit-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1-debuginfo-32bit-228", rpm:"libudev1-debuginfo-32bit-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname-32bit-228", rpm:"nss-myhostname-32bit-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname-debuginfo-32bit-228", rpm:"nss-myhostname-debuginfo-32bit-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-32bit-228", rpm:"systemd-32bit-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-debuginfo-32bit-228", rpm:"systemd-debuginfo-32bit-228~65.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
