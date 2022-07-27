###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_1265_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for PHP SUSE-SU-2015:1265-1 (PHP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850783");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-13 15:34:07 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2015-3411", "CVE-2015-3412", "CVE-2015-4148", "CVE-2015-4598",
                "CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4601", "CVE-2015-4602",
                "CVE-2015-4603", "CVE-2015-4643", "CVE-2015-4644");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for PHP SUSE-SU-2015:1265-1 (PHP)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'PHP'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The PHP script interpreter was updated to fix various security issues:

  * CVE-2015-4602 [bnc#935224]: Fixed an incomplete Class
  unserialization type confusion.

  * CVE-2015-4599, CVE-2015-4600, CVE-2015-4601 [bnc#935226]: Fixed type
  confusion issues in unserialize() with various SOAP methods.

  * CVE-2015-4603 [bnc#935234]: Fixed exception::getTraceAsString type
  confusion issue after unserialize.

  * CVE-2015-4644 [bnc#935274]: Fixed a crash in php_pgsql_meta_data.

  * CVE-2015-4643 [bnc#935275]: Fixed an integer overflow in
  ftp_genlist() that could result in a heap overflow.

  * CVE-2015-3411, CVE-2015-3412, CVE-2015-4598 [bnc#935227],
  [bnc#935232]: Added missing null byte checks for paths in various
  PHP extensions.

  * CVE-2015-4148 [bnc#933227]: Fixed a SoapClient's do_soap_call() type
  confusion after unserialize() information disclosure.

  Also the following bug were fixed:

  * fix a segmentation fault in odbc_fetch_array [bnc#935074]

  * fix timezone map [bnc#919080]");

  script_tag(name:"affected", value:"PHP on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLES11.0SP3")
{

  if ((res = isrpmvuln(pkg:"apache2-mod_php53", rpm:"apache2-mod_php53~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53", rpm:"php53~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-bcmath", rpm:"php53-bcmath~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-bz2", rpm:"php53-bz2~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-calendar", rpm:"php53-calendar~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-ctype", rpm:"php53-ctype~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-curl", rpm:"php53-curl~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-dba", rpm:"php53-dba~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-dom", rpm:"php53-dom~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-exif", rpm:"php53-exif~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-fastcgi", rpm:"php53-fastcgi~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-fileinfo", rpm:"php53-fileinfo~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-ftp", rpm:"php53-ftp~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-gd", rpm:"php53-gd~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-gettext", rpm:"php53-gettext~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-gmp", rpm:"php53-gmp~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-iconv", rpm:"php53-iconv~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-intl", rpm:"php53-intl~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-json", rpm:"php53-json~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-ldap", rpm:"php53-ldap~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-mbstring", rpm:"php53-mbstring~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-mcrypt", rpm:"php53-mcrypt~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-mysql", rpm:"php53-mysql~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-odbc", rpm:"php53-odbc~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-openssl", rpm:"php53-openssl~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-pcntl", rpm:"php53-pcntl~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-pdo", rpm:"php53-pdo~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-pear", rpm:"php53-pear~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-pgsql", rpm:"php53-pgsql~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-pspell", rpm:"php53-pspell~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-shmop", rpm:"php53-shmop~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-snmp", rpm:"php53-snmp~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-soap", rpm:"php53-soap~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-suhosin", rpm:"php53-suhosin~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-sysvmsg", rpm:"php53-sysvmsg~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-sysvsem", rpm:"php53-sysvsem~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-sysvshm", rpm:"php53-sysvshm~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-tokenizer", rpm:"php53-tokenizer~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-wddx", rpm:"php53-wddx~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-xmlreader", rpm:"php53-xmlreader~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-xmlrpc", rpm:"php53-xmlrpc~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-xmlwriter", rpm:"php53-xmlwriter~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-xsl", rpm:"php53-xsl~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-zip", rpm:"php53-zip~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php53-zlib", rpm:"php53-zlib~5.3.17~0.43.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
