###############################################################################
# OpenVAS Vulnerability Test
# $Id: ELSA-2013-0685.nasl 11688 2018-09-28 13:36:28Z cfischer $
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
  script_oid("1.3.6.1.4.1.25623.1.0.123654");
  script_version("$Revision: 11688 $");
  script_tag(name:"creation_date", value:"2015-10-06 14:06:50 +0300 (Tue, 06 Oct 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 15:36:28 +0200 (Fri, 28 Sep 2018) $");
  script_name("Oracle Linux Local Check: ELSA-2013-0685");
  script_tag(name:"insight", value:"ELSA-2013-0685 - perl security update. Please see the references for more insight.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Oracle Linux Local Security Checks ELSA-2013-0685");
  script_xref(name:"URL", value:"http://linux.oracle.com/errata/ELSA-2013-0685.html");
  script_cve_id("CVE-2012-5195", "CVE-2012-5526", "CVE-2012-6329", "CVE-2013-1667");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux(5|6)");
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
  if ((res = isrpmvuln(pkg:"perl", rpm:"perl~5.8.8~40.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-suidperl", rpm:"perl-suidperl~5.8.8~40.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"perl", rpm:"perl~5.10.1~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Archive-Extract", rpm:"perl-Archive-Extract~0.38~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Archive-Tar", rpm:"perl-Archive-Tar~1.58~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-CGI", rpm:"perl-CGI~3.51~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-CPAN", rpm:"perl-CPAN~1.9402~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-CPANPLUS", rpm:"perl-CPANPLUS~0.88~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Compress-Raw-Bzip2", rpm:"perl-Compress-Raw-Bzip2~2.020~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Compress-Raw-Zlib", rpm:"perl-Compress-Raw-Zlib~2.020~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Compress-Zlib", rpm:"perl-Compress-Zlib~2.020~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Digest-SHA", rpm:"perl-Digest-SHA~5.47~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-ExtUtils-CBuilder", rpm:"perl-ExtUtils-CBuilder~0.27~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-ExtUtils-Embed", rpm:"perl-ExtUtils-Embed~1.28~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-ExtUtils-MakeMaker", rpm:"perl-ExtUtils-MakeMaker~6.55~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-ExtUtils-ParseXS", rpm:"perl-ExtUtils-ParseXS~2.2003.0~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-File-Fetch", rpm:"perl-File-Fetch~0.26~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-IO-Compress-Base", rpm:"perl-IO-Compress-Base~2.020~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-IO-Compress-Bzip2", rpm:"perl-IO-Compress-Bzip2~2.020~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-IO-Compress-Zlib", rpm:"perl-IO-Compress-Zlib~2.020~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-IO-Zlib", rpm:"perl-IO-Zlib~1.09~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-IPC-Cmd", rpm:"perl-IPC-Cmd~0.56~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Locale-Maketext-Simple", rpm:"perl-Locale-Maketext-Simple~0.18~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Log-Message", rpm:"perl-Log-Message~0.02~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Log-Message-Simple", rpm:"perl-Log-Message-Simple~0.04~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Module-Build", rpm:"perl-Module-Build~0.3500~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Module-CoreList", rpm:"perl-Module-CoreList~2.18~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Module-Load", rpm:"perl-Module-Load~0.16~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Module-Load-Conditional", rpm:"perl-Module-Load-Conditional~0.30~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Module-Loaded", rpm:"perl-Module-Loaded~0.02~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Module-Pluggable", rpm:"perl-Module-Pluggable~3.90~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Object-Accessor", rpm:"perl-Object-Accessor~0.34~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Package-Constants", rpm:"perl-Package-Constants~0.02~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Params-Check", rpm:"perl-Params-Check~0.26~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Parse-CPAN-Meta", rpm:"perl-Parse-CPAN-Meta~1.40~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Pod-Escapes", rpm:"perl-Pod-Escapes~1.04~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Pod-Simple", rpm:"perl-Pod-Simple~3.13~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Term-UI", rpm:"perl-Term-UI~0.20~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Test-Harness", rpm:"perl-Test-Harness~3.17~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Test-Simple", rpm:"perl-Test-Simple~0.92~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Time-HiRes", rpm:"perl-Time-HiRes~1.9721~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-Time-Piece", rpm:"perl-Time-Piece~1.15~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-core", rpm:"perl-core~5.10.1~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-devel", rpm:"perl-devel~5.10.1~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-libs", rpm:"perl-libs~5.10.1~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-parent", rpm:"perl-parent~0.221~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-suidperl", rpm:"perl-suidperl~5.10.1~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"perl-version", rpm:"perl-version~0.77~130.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }

}
if (__pkg_match) exit(99);
  exit(0);

