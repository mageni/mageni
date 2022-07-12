###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3695_1.nasl 12799 2018-12-14 07:38:54Z ckuersteiner $
#
# SuSE Update for systemd openSUSE-SU-2018:3695-1 (systemd)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.852121");
  script_version("$Revision: 12799 $");
  script_cve_id("CVE-2018-15686", "CVE-2018-15688");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-14 08:38:54 +0100 (Fri, 14 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-11-10 05:59:41 +0100 (Sat, 10 Nov 2018)");
  script_name("SuSE Update for systemd openSUSE-SU-2018:3695-1 (systemd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-11/msg00007.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the openSUSE-SU-2018:3695_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes the following issues:

  Security issues fixed:

  - CVE-2018-15688: A buffer overflow vulnerability in the dhcp6 client of
  systemd allowed a malicious dhcp6 server to overwrite heap memory in
  systemd-networkd. (bsc#1113632)

  - CVE-2018-15686: A vulnerability in unit_deserialize of systemd allows an
  attacker to supply arbitrary state across systemd re-execution via
  NotifyAccess. This can be used to improperly influence systemd execution
  and possibly lead to root privilege escalation. (bsc#1113665)

  Non security issues fixed:

  - dhcp6: split assert_return() to be more debuggable when hit

  - core: skip unit deserialization and move to the next one when
  unit_deserialize() fails

  - core: properly handle deserialization of unknown unit types (#6476)

  - core: don't create Requires for workdir if 'missing ok' (bsc#1113083)

  - logind: use manager_get_user_by_pid() where appropriate

  - logind: rework manager_get_{usersession}_by_pid() a bit

  - login: fix user@.service case, so we don't allow nested sessions (#8051)
  (bsc#1112024)

  - core: be more defensive if we can't determine per-connection socket peer
  (#7329)

  - core: introduce systemd.early_core_pattern= kernel cmdline option

  - core: add missing 'continue' statement

  - core/mount: fstype may be NULL

  - journald: don't ship systemd-journald-audit.socket (bsc#1109252)

  - core: make 'tmpfs' dependencies on swapfs a 'default' dep, not an
  'implicit' (bsc#1110445)

  - mount: make sure we unmount tmpfs mounts before we deactivate swaps
  (#7076)

  - detect-virt: do not try to read all of /proc/cpuinfo (bsc#1109197)

  - emergency: make sure console password agents don't interfere with the
  emergency shell

  - man: document that 'nofail' also has an effect on ordering

  - journald: take leading spaces into account in syslog_parse_identifier

  - journal: do not remove multiple spaces after identifier in syslog message

  - syslog: fix segfault in syslog_parse_priority()

  - journal: fix syslog_parse_identifier()

  - install: drop left-over debug message (#6913)

  - Ship systemd-sysv-install helper via the main package This script was
  part of systemd-sysvinit sub-package but it was wrong since
  systemd-sysv-install is a script used to redirect enable/disable
  operations to chkconfig when the unit targets are sysv init scripts.
  Therefore it's never been a SySV init tool.

  - Add udev.no-partlabel-links kernel command-line option. This option can
  be used to disable the generation of the by-partlabel symlinks
  regardless of the name used. (bsc#1089761)

  - man: SystemMaxUse= clar ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"systemd on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0-debuginfo", rpm:"libsystemd0-debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0-mini", rpm:"libsystemd0-mini~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0-mini-debuginfo", rpm:"libsystemd0-mini-debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-devel", rpm:"libudev-devel~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-mini-devel", rpm:"libudev-mini-devel~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-mini1", rpm:"libudev-mini1~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-mini1-debuginfo", rpm:"libudev-mini1-debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1-debuginfo", rpm:"libudev1-debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname", rpm:"nss-myhostname~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname-debuginfo", rpm:"nss-myhostname-debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-mymachines", rpm:"nss-mymachines~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-mymachines-debuginfo", rpm:"nss-mymachines-debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-systemd", rpm:"nss-systemd~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-systemd-debuginfo", rpm:"nss-systemd-debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd", rpm:"systemd~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-container", rpm:"systemd-container~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-container-debuginfo", rpm:"systemd-container-debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-coredump", rpm:"systemd-coredump~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-coredump-debuginfo", rpm:"systemd-coredump-debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-debuginfo", rpm:"systemd-debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-debugsource", rpm:"systemd-debugsource~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-devel", rpm:"systemd-devel~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-logger", rpm:"systemd-logger~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini", rpm:"systemd-mini~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-container-mini", rpm:"systemd-mini-container-mini~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-container-mini-debuginfo", rpm:"systemd-mini-container-mini-debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-coredump-mini", rpm:"systemd-mini-coredump-mini~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-coredump-mini-debuginfo", rpm:"systemd-mini-coredump-mini-debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-debuginfo", rpm:"systemd-mini-debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-debugsource", rpm:"systemd-mini-debugsource~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-devel", rpm:"systemd-mini-devel~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-sysvinit", rpm:"systemd-mini-sysvinit~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev", rpm:"udev~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-debuginfo", rpm:"udev-debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-mini", rpm:"udev-mini~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-mini-debuginfo", rpm:"udev-mini-debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-bash-completion", rpm:"systemd-bash-completion~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-bash-completion", rpm:"systemd-mini-bash-completion~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~32bit~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~32bit~debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-devel", rpm:"libudev-devel~32bit~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~32bit~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~32bit~debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname", rpm:"nss-myhostname~32bit~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname", rpm:"nss-myhostname~32bit~debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-mymachines", rpm:"nss-mymachines~32bit~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-mymachines", rpm:"nss-mymachines~32bit~debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd", rpm:"systemd~32bit~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd", rpm:"systemd~32bit~debuginfo~234~lp150.20.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
