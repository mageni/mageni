###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for php RHSA-2015:1135-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871379");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-06-24 06:13:17 +0200 (Wed, 24 Jun 2015)");
  script_cve_id("CVE-2014-8142", "CVE-2014-9652", "CVE-2014-9705", "CVE-2014-9709",
                "CVE-2015-0231", "CVE-2015-0232", "CVE-2015-0273", "CVE-2015-2301",
                "CVE-2015-2348", "CVE-2015-2783", "CVE-2015-2787", "CVE-2015-3307",
                "CVE-2015-3329", "CVE-2015-3330", "CVE-2015-3411", "CVE-2015-3412",
                "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4025",
                "CVE-2015-4026", "CVE-2015-4147", "CVE-2015-4148", "CVE-2015-4598",
                "CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4601", "CVE-2015-4602",
                "CVE-2015-4603", "CVE-2015-4604", "CVE-2015-4605", "CVE-2006-7243");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for php RHSA-2015:1135-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'php'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"PHP is an HTML-embedded scripting language commonly used with the Apache
HTTP Server.

A flaw was found in the way the PHP module for the Apache httpd web server
handled pipelined requests. A remote attacker could use this flaw to
trigger the execution of a PHP script in a deinitialized interpreter,
causing it to crash or, possibly, execute arbitrary code. (CVE-2015-3330)

A flaw was found in the way PHP parsed multipart HTTP POST requests. A
specially crafted request could cause PHP to use an excessive amount of CPU
time. (CVE-2015-4024)

An uninitialized pointer use flaw was found in PHP's Exif extension. A
specially crafted JPEG or TIFF file could cause a PHP application using the
exif_read_data() function to crash or, possibly, execute arbitrary code
with the privileges of the user running that PHP application.
(CVE-2015-0232)

An integer overflow flaw leading to a heap-based buffer overflow was found
in the way PHP's FTP extension parsed file listing FTP server responses. A
malicious FTP server could use this flaw to cause a PHP application to
crash or, possibly, execute arbitrary code. (CVE-2015-4022)

Multiple flaws were discovered in the way PHP performed object
unserialization. Specially crafted input processed by the unserialize()
function could cause a PHP application to crash or, possibly, execute
arbitrary code. (CVE-2014-8142, CVE-2015-0231, CVE-2015-0273,
CVE-2015-2787, CVE-2015-4147, CVE-2015-4148, CVE-2015-4599, CVE-2015-4600,
CVE-2015-4601, CVE-2015-4602, CVE-2015-4603)

It was found that certain PHP functions did not properly handle file names
containing a NULL character. A remote attacker could possibly use this flaw
to make a PHP script access unexpected files and bypass intended file
system access restrictions. (CVE-2015-2348, CVE-2015-4025, CVE-2015-4026,
CVE-2015-3411, CVE-2015-3412, CVE-2015-4598)

Multiple flaws were found in the way the way PHP's Phar extension parsed
Phar archives. A specially crafted archive could cause PHP to crash or,
possibly, execute arbitrary code when opened. (CVE-2015-2301,
CVE-2015-2783, CVE-2015-3307, CVE-2015-3329, CVE-2015-4021)

Multiple flaws were found in PHP's File Information (fileinfo) extension.
A remote attacker could cause a PHP application to crash if it used
fileinfo to identify type of attacker supplied files. (CVE-2014-9652,
CVE-2015-4604, CVE-2015-4605)

A heap buffer overflow flaw was found in the enchant_broker_request_dict()
function of PHP's enchant extension. An attacker able to make a PHP
application enchant dictionaries could possibly cause it to crash.
(CVE-2014-9705)

A buffer over-read flaw  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"php on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-June/msg00023.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"php", rpm:"php~5.4.16~36.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~5.4.16~36.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-common", rpm:"php-common~5.4.16~36.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-debuginfo", rpm:"php-debuginfo~5.4.16~36.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~5.4.16~36.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~5.4.16~36.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mysql", rpm:"php-mysql~5.4.16~36.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~5.4.16~36.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pdo", rpm:"php-pdo~5.4.16~36.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~5.4.16~36.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-process", rpm:"php-process~5.4.16~36.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-recode", rpm:"php-recode~5.4.16~36.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-soap", rpm:"php-soap~5.4.16~36.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-xml", rpm:"php-xml~5.4.16~36.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-xmlrpc", rpm:"php-xmlrpc~5.4.16~36.el7_1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
