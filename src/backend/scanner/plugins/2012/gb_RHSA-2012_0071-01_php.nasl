###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for php RHSA-2012:0071-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-January/msg00027.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870533");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-01 11:35:29 +0530 (Wed, 01 Feb 2012)");
  script_cve_id("CVE-2011-0708", "CVE-2011-1466", "CVE-2011-2202", "CVE-2011-4566",
                "CVE-2011-4885");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_name("RedHat Update for php RHSA-2012:0071-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_4");
  script_tag(name:"affected", value:"php on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Server.

  It was found that the hashing routine used by PHP arrays was susceptible
  to predictable hash collisions. If an HTTP POST request to a PHP
  application contained many parameters whose names map to the same hash
  value, a large amount of CPU time would be consumed. This flaw has been
  mitigated by adding a new configuration directive, max_input_vars, that
  limits the maximum number of parameters processed per request. By
  default, max_input_vars is set to 1000. (CVE-2011-4885)

  An integer overflow flaw was found in the PHP exif extension. On 32-bit
  systems, a specially-crafted image file could cause the PHP interpreter to
  crash or disclose portions of its memory when a PHP script tries to extract
  Exchangeable image file format (Exif) metadata from the image file.
  (CVE-2011-4566)

  An insufficient input validation flaw, leading to a buffer over-read, was
  found in the PHP exif extension. A specially-crafted image file could cause
  the PHP interpreter to crash when a PHP script tries to extract
  Exchangeable image file format (Exif) metadata from the image file.
  (CVE-2011-0708)

  An integer overflow flaw was found in the PHP calendar extension. A remote
  attacker able to make a PHP script call SdnToJulian() with a large value
  could cause the PHP interpreter to crash. (CVE-2011-1466)

  An off-by-one flaw was found in PHP. If an attacker uploaded a file with a
  specially-crafted file name it could cause a PHP script to attempt to write
  a file to the root (/) directory. By default, PHP runs as the 'apache'
  user, preventing it from writing to the root directory. (CVE-2011-2202)

  Red Hat would like to thank oCERT for reporting CVE-2011-4885. oCERT
  acknowledges Julian Waelde and Alexander Klink as the original reporters of
  CVE-2011-4885.

  All php users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. After installing the updated
  packages, the httpd daemon must be restarted for the update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"php", rpm:"php~4.3.9~3.35", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-debuginfo", rpm:"php-debuginfo~4.3.9~3.35", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~4.3.9~3.35", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-domxml", rpm:"php-domxml~4.3.9~3.35", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-gd", rpm:"php-gd~4.3.9~3.35", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-imap", rpm:"php-imap~4.3.9~3.35", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~4.3.9~3.35", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mbstring", rpm:"php-mbstring~4.3.9~3.35", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mysql", rpm:"php-mysql~4.3.9~3.35", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-ncurses", rpm:"php-ncurses~4.3.9~3.35", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~4.3.9~3.35", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear", rpm:"php-pear~4.3.9~3.35", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~4.3.9~3.35", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-snmp", rpm:"php-snmp~4.3.9~3.35", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-xmlrpc", rpm:"php-xmlrpc~4.3.9~3.35", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
