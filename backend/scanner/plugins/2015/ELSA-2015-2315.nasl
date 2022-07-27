###############################################################################
# OpenVAS Vulnerability Test
# $Id: ELSA-2015-2315.nasl 11688 2018-09-28 13:36:28Z cfischer $
#
# Oracle Linux Local Check
#
# Authors:
# Eero Volotinen <eero.volotinen@solinor.com>
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122782");
  script_version("$Revision: 11688 $");
  script_tag(name:"creation_date", value:"2015-11-25 13:18:49 +0200 (Wed, 25 Nov 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 15:36:28 +0200 (Fri, 28 Sep 2018) $");
  script_name("Oracle Linux Local Check: ELSA-2015-2315");
  script_tag(name:"insight", value:"ELSA-2015-2315 -  NetworkManager security, bug fix, and enhancement update. Please see the references for more insight.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Oracle Linux Local Security Checks ELSA-2015-2315");
  script_xref(name:"URL", value:"http://linux.oracle.com/errata/ELSA-2015-2315.html");
  script_cve_id("CVE-2015-0272", "CVE-2015-2924");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Eero Volotinen");
  script_family("Oracle Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"ModemManager", rpm:"ModemManager~1.1.0~8.git20130913.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"ModemManager-devel", rpm:"ModemManager-devel~1.1.0~8.git20130913.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"ModemManager-glib", rpm:"ModemManager-glib~1.1.0~8.git20130913.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"ModemManager-glib-devel", rpm:"ModemManager-glib-devel~1.1.0~8.git20130913.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"ModemManager-vala", rpm:"ModemManager-vala~1.1.0~8.git20130913.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-adsl", rpm:"NetworkManager-adsl~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-bluetooth", rpm:"NetworkManager-bluetooth~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-config-routing-rules", rpm:"NetworkManager-config-routing-rules~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-config-server", rpm:"NetworkManager-config-server~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-devel", rpm:"NetworkManager-devel~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-glib", rpm:"NetworkManager-glib~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-glib-devel", rpm:"NetworkManager-glib-devel~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-libnm", rpm:"NetworkManager-libnm~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-libnm-devel", rpm:"NetworkManager-libnm-devel~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-libreswan", rpm:"NetworkManager-libreswan~1.0.6~3.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-libreswan-gnome", rpm:"NetworkManager-libreswan-gnome~1.0.6~3.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-team", rpm:"NetworkManager-team~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-tui", rpm:"NetworkManager-tui~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-wifi", rpm:"NetworkManager-wifi~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"NetworkManager-wwan", rpm:"NetworkManager-wwan~1.0.6~27.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"libnm-gtk", rpm:"libnm-gtk~1.0.6~2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"libnm-gtk-devel", rpm:"libnm-gtk-devel~1.0.6~2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"network-manager-applet", rpm:"network-manager-applet~1.0.6~2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"nm-connection-editor", rpm:"nm-connection-editor~1.0.6~2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);
  }

}
if (__pkg_match) exit(99);
  exit(0);

