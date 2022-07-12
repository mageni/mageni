# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852325");
  script_version("$Revision: 13991 $");
  script_cve_id("CVE-2019-6454");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 11:29:52 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-01 04:15:17 +0100 (Fri, 01 Mar 2019)");
  script_name("SuSE Update for systemd openSUSE-SU-2019:0268-1 (systemd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-02/msg00075.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the openSUSE-SU-2019:0268_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes the following issues:

  Security vulnerability fixed:

  - CVE-2019-6454: Fixed a crash of PID1 by sending specially crafted D-BUS
  message on the system bus by an unprivileged user (bsc#1125352)

  Other bug fixes and changes:

  - journal-remote: set a limit on the number of fields in a message

  - journal-remote: verify entry length from header

  - journald: set a limit on the number of fields (1k)

  - journald: do not store the iovec entry for process commandline on stack

  - core: include Found state in device dumps

  - device: fix serialization and deserialization of DeviceFound

  - fix path in btrfs rule (#6844)

  - assemble multidevice btrfs volumes without external tools (#6607)
  (bsc#1117025)

  - Update systemd-system.conf.xml (bsc#1122000)

  - units: inform user that the default target is started after exiting from
  rescue or emergency mode

  - manager: don't skip sigchld handler for main and control pid for
  services (#3738)

  - core: Add helper functions unit_{main, control}_pid

  - manager: Fixing a debug printf formatting mistake (#3640)

  - manager: Only invoke a single sigchld per unit within a cleanup cycle
  (bsc#1117382)

  - core: update invoke_sigchld_event() to handle NULL - sigchld_event()

  - sd-event: expose the event loop iteration counter via
  sd_event_get_iteration() (#3631)

  - unit: rework a bit how we keep the service fdstore from being destroyed
  during service restart (bsc#1122344)

  - core: when restarting services, don't close fds

  - cryptsetup: Add dependency on loopback setup to generated units

  - journal-gateway: use localStorage['cursor'] only when it has valid value

  - journal-gateway: explicitly declare local variables

  - analyze: actually select longest activated-time of services

  - sd-bus: fix implicit downcast of bitfield reported by LGTM

  - core: free lines after reading them (bsc#1123892)

  - pam_systemd: reword message about not creating a session (bsc#1111498)

  - pam_systemd: suppress LOG_DEBUG log messages if debugging is off
  (bsc#1111498)

  - main: improve RLIMIT_NOFILE handling (#5795) (bsc#1120658)

  - sd-bus: if we receive an invalid dbus message, ignore and proceed

  - automount: don't pass non-blocking pipe to kernel.

  - units: make sure initrd-cleanup.service terminates before switching to
  rootfs (bsc#1123333)

  - units: add Wants=initrd-cleanup.service to initrd-switch-root.target
  (#4345) (bsc#1123333)

  This update was imported from the SUSE:SLE-12-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  insta ...

  Description truncated, please see the referenced URL(s) for more information.");

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

  if ((res = isrpmvuln(pkg:"libsystemd0-228", rpm:"libsystemd0-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0-debuginfo-228", rpm:"libsystemd0-debuginfo-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0-mini-228", rpm:"libsystemd0-mini-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0-mini-debuginfo-228", rpm:"libsystemd0-mini-debuginfo-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-devel-228", rpm:"libudev-devel-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-mini-devel-228", rpm:"libudev-mini-devel-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-mini1-228", rpm:"libudev-mini1-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-mini1-debuginfo-228", rpm:"libudev-mini1-debuginfo-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1-228", rpm:"libudev1-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1-debuginfo-228", rpm:"libudev1-debuginfo-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname-228", rpm:"nss-myhostname-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname-debuginfo-228", rpm:"nss-myhostname-debuginfo-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-mymachines-228", rpm:"nss-mymachines-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-mymachines-debuginfo-228", rpm:"nss-mymachines-debuginfo-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-228", rpm:"systemd-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-debuginfo-228", rpm:"systemd-debuginfo-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-debugsource-228", rpm:"systemd-debugsource-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-devel-228", rpm:"systemd-devel-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-logger-228", rpm:"systemd-logger-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-228", rpm:"systemd-mini-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-debuginfo-228", rpm:"systemd-mini-debuginfo-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-debugsource-228", rpm:"systemd-mini-debugsource-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-devel-228", rpm:"systemd-mini-devel-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-sysvinit-228", rpm:"systemd-mini-sysvinit-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-sysvinit-228", rpm:"systemd-sysvinit-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-228", rpm:"udev-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-debuginfo-228", rpm:"udev-debuginfo-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-mini-228", rpm:"udev-mini-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-mini-debuginfo-228", rpm:"udev-mini-debuginfo-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0-32bit-228", rpm:"libsystemd0-32bit-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0-debuginfo-32bit-228", rpm:"libsystemd0-debuginfo-32bit-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1-32bit-228", rpm:"libudev1-32bit-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1-debuginfo-32bit-228", rpm:"libudev1-debuginfo-32bit-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname-32bit-228", rpm:"nss-myhostname-32bit-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname-debuginfo-32bit-228", rpm:"nss-myhostname-debuginfo-32bit-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-32bit-228", rpm:"systemd-32bit-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-debuginfo-32bit-228", rpm:"systemd-debuginfo-32bit-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-bash-completion-228", rpm:"systemd-bash-completion-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-bash-completion-228", rpm:"systemd-mini-bash-completion-228~68.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
