###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_1101_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for systemd openSUSE-SU-2016:1101-1 (systemd)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851281");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-04-20 05:19:14 +0200 (Wed, 20 Apr 2016)");
  script_cve_id("CVE-2014-9770", "CVE-2015-8842");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for systemd openSUSE-SU-2016:1101-1 (systemd)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for systemd fixes several issues.

  These security issues were fixed:

  - CVE-2014-9770, CVE-2015-8842: Don't allow read access to journal files
  to users (boo#972612)

  These non-security issues were fixed:

  - Import commit 523777609a04fe9e590420e89f94ef07e3719baa: e5e362a udev:
  exclude MD from block device ownership event locking 8839413 udev:
  really exclude device-mapper from block device ownership event locking
  66782e6 udev: exclude device-mapper from block device ownership event
  locking (boo#972727) 1386f57 tmpfiles: explicitly set mode for /run/log
  faadb74 tmpfiles: don't allow read access to journal files to users not
  in systemd-journal 9b1ef37 tmpfiles: don't apply sgid and executable bit
  to journal files, only the directories they are contained in 011c39f
  tmpfiles: add ability to mask access mode by pre-existing access mode on
  files/directories 07e2d60 tmpfiles: get rid of 'm' lines d504e28
  tmpfiles: various modernizations f97250d systemctl: no need to pass

  - -all if inactive is explicitly requested in list-units (boo#967122)
  2686573 fstab-generator: fix automount option and don't start associated
  mount unit at boot (boo#970423) 5c1637d login: support more than just
  power-gpio-key (fate#318444) (boo#970860) 2c95ecd logind: add standard
  gpio power button support (fate#318444) (boo#970860) af3eb93 Revert
  'log-target-null-instead-kmsg' 555dad4 shorten hostname before checking
  for trailing dot (boo#965897) 522194c Revert 'log: honour the kernel's
  quiet cmdline argument' (boo#963230) cc94e47 transaction: downgrade
  warnings about wanted unit which are not found (boo#960158) eb3cfb3
  Revert 'vhangup-on-all-consoles' 0c28752 remove WorkingDirectory
  parameter from emergency, rescue and console-shell.service (boo#959886)
  1d6d840 Fix wrong substitution variable name in
  systemd-udev-root-symlink.service.in (boo#964355)

  - Don't ship boot.udev and systemd-journald.init anymore. It was used
  during the systemd transition when both sysvinit and systemd could be
  used on the same system");
  script_tag(name:"affected", value:"systemd on openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"libgudev-1_0-0", rpm:"libgudev-1_0-0~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgudev-1_0-0-debuginfo", rpm:"libgudev-1_0-0-debuginfo~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgudev-1_0-devel", rpm:"libgudev-1_0-devel~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-devel", rpm:"libudev-devel~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-mini-devel", rpm:"libudev-mini-devel~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-mini1", rpm:"libudev-mini1~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev-mini1-debuginfo", rpm:"libudev-mini1-debuginfo~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1-debuginfo", rpm:"libudev1-debuginfo~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname", rpm:"nss-myhostname~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname-debuginfo", rpm:"nss-myhostname-debuginfo~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd", rpm:"systemd~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-debuginfo", rpm:"systemd-debuginfo~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-debugsource", rpm:"systemd-debugsource~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-devel", rpm:"systemd-devel~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-journal-gateway", rpm:"systemd-journal-gateway~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-journal-gateway-debuginfo", rpm:"systemd-journal-gateway-debuginfo~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-logger", rpm:"systemd-logger~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini", rpm:"systemd-mini~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-debuginfo", rpm:"systemd-mini-debuginfo~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-debugsource", rpm:"systemd-mini-debugsource~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-devel", rpm:"systemd-mini-devel~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-mini-sysvinit", rpm:"systemd-mini-sysvinit~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"typelib-1_0-GUdev-1_0", rpm:"typelib-1_0-GUdev-1_0~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev", rpm:"udev~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-debuginfo", rpm:"udev-debuginfo~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-mini", rpm:"udev-mini~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-mini-debuginfo", rpm:"udev-mini-debuginfo~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-bash-completion", rpm:"systemd-bash-completion~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgudev-1_0-0-32bit", rpm:"libgudev-1_0-0-32bit~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgudev-1_0-0-debuginfo-32bit", rpm:"libgudev-1_0-0-debuginfo-32bit~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1-32bit", rpm:"libudev1-32bit~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libudev1-debuginfo-32bit", rpm:"libudev1-debuginfo-32bit~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname-32bit", rpm:"nss-myhostname-32bit~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-myhostname-debuginfo-32bit", rpm:"nss-myhostname-debuginfo-32bit~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-32bit", rpm:"systemd-32bit~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-debuginfo-32bit", rpm:"systemd-debuginfo-32bit~210.1459453449.5237776~25.37.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
