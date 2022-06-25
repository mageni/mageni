###############################################################################
# OpenVAS Vulnerability Test
# $Id: ELSA-2008-0497.nasl 11688 2018-09-28 13:36:28Z cfischer $
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
  script_oid("1.3.6.1.4.1.25623.1.0.122574");
  script_version("$Revision: 11688 $");
  script_tag(name:"creation_date", value:"2015-10-08 14:48:26 +0300 (Thu, 08 Oct 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 15:36:28 +0200 (Fri, 28 Sep 2018) $");
  script_name("Oracle Linux Local Check: ELSA-2008-0497");
  script_tag(name:"insight", value:"ELSA-2008-0497 - sblim security update. Please see the references for more insight.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Oracle Linux Local Security Checks ELSA-2008-0497");
  script_xref(name:"URL", value:"http://linux.oracle.com/errata/ELSA-2008-0497.html");
  script_cve_id("CVE-2008-1951");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");
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

if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"sblim-cim-client", rpm:"sblim-cim-client~1.3.3~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cim-client-javadoc", rpm:"sblim-cim-client-javadoc~1~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cim-client-manual", rpm:"sblim-cim-client-manual~1~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-base", rpm:"sblim-cmpi-base~1.5.5~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-base-devel", rpm:"sblim-cmpi-base-devel~1.5.5~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-base-test", rpm:"sblim-cmpi-base-test~1.5.5~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-devel", rpm:"sblim-cmpi-devel~1.0.4~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-dns", rpm:"sblim-cmpi-dns~0.5.2~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-dns-devel", rpm:"sblim-cmpi-dns-devel~1~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-dns-test", rpm:"sblim-cmpi-dns-test~1~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-fsvol", rpm:"sblim-cmpi-fsvol~1.4.4~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-fsvol-devel", rpm:"sblim-cmpi-fsvol-devel~1.4.4~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-fsvol-test", rpm:"sblim-cmpi-fsvol-test~1.4.4~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-network", rpm:"sblim-cmpi-network~1.3.8~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-network-devel", rpm:"sblim-cmpi-network-devel~1.3.8~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-network-test", rpm:"sblim-cmpi-network-test~1.3.8~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-nfsv3", rpm:"sblim-cmpi-nfsv3~1.0.14~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-nfsv3-test", rpm:"sblim-cmpi-nfsv3-test~1.0.14~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-nfsv4", rpm:"sblim-cmpi-nfsv4~1.0.12~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-nfsv4-test", rpm:"sblim-cmpi-nfsv4-test~1.0.12~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-params", rpm:"sblim-cmpi-params~1.2.6~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-params-test", rpm:"sblim-cmpi-params-test~1.2.6~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-samba", rpm:"sblim-cmpi-samba~0.5.2~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-samba-devel", rpm:"sblim-cmpi-samba-devel~1~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-samba-test", rpm:"sblim-cmpi-samba-test~1~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-sysfs", rpm:"sblim-cmpi-sysfs~1.1.9~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-sysfs-test", rpm:"sblim-cmpi-sysfs-test~1.1.9~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-syslog", rpm:"sblim-cmpi-syslog~0.7.11~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-cmpi-syslog-test", rpm:"sblim-cmpi-syslog-test~0.7.11~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-gather", rpm:"sblim-gather~2.1.2~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-gather-devel", rpm:"sblim-gather-devel~2.1.2~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-gather-provider", rpm:"sblim-gather-provider~2.1.2~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-gather-test", rpm:"sblim-gather-test~2.1.2~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-testsuite", rpm:"sblim-testsuite~1.2.4~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-tools-libra", rpm:"sblim-tools-libra~0.2.3~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-tools-libra-devel", rpm:"sblim-tools-libra-devel~0.2.3~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"sblim-wbemcli", rpm:"sblim-wbemcli~1.5.1~31.0.1.el5_2.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }

}
if (__pkg_match) exit(99);
  exit(0);

