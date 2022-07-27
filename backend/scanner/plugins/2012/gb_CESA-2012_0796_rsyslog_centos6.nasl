###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for rsyslog CESA-2012:0796 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-July/018711.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881131");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:18:17 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-4623");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for rsyslog CESA-2012:0796 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rsyslog'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"rsyslog on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The rsyslog packages provide an enhanced, multi-threaded syslog daemon.

  A numeric truncation error, leading to a heap-based buffer overflow, was
  found in the way the rsyslog imfile module processed text files containing
  long lines. An attacker could use this flaw to crash the rsyslogd daemon
  or, possibly, execute arbitrary code with the privileges of rsyslogd, if
  they are able to cause a long line to be written to a log file that
  rsyslogd monitors with imfile. The imfile module is not enabled by default.
  (CVE-2011-4623)

  Bug fixes:

  * Several variables were incorrectly deinitialized with Transport Layer
  Security (TLS) transport and keys in PKCS#8 format. The rsyslogd daemon
  aborted with a segmentation fault when keys in this format were provided.
  Now, the variables are correctly deinitialized. (BZ#727380)

  * Previously, the imgssapi plug-in initialization was incomplete. As a
  result, the rsyslogd daemon aborted when configured to provide a GSSAPI
  listener. Now, the plug-in is correctly initialized. (BZ#756664)

  * The fully qualified domain name (FQDN) for the localhost used in messages
  was the first alias found. This did not always produce the expected result
  on multihomed hosts. With this update, the algorithm uses the alias that
  corresponds to the hostname. (BZ#767527)

  * The gtls module leaked a file descriptor every time it was loaded due to
  an error in the GnuTLS library. No new files or network connections could
  be opened when the limit for the file descriptor count was reached. This
  update modifies the gtls module so that it is not unloaded during the
  process lifetime. (BZ#803550)

  * rsyslog could not override the hostname to set an alternative hostname
  for locally generated messages. Now, the local hostname can be overridden.
  (BZ#805424)

  * The rsyslogd init script did not pass the lock file path to the 'status'
  action. As a result, the lock file was ignored and a wrong exit code was
  returned. This update modifies the init script to pass the lock file to
  the 'status' action. Now, the correct exit code is returned. (BZ#807608)

  * Data could be incorrectly deinitialized when rsyslogd was supplied with
  malformed spool files. The rsyslogd daemon could be aborted with a
  segmentation fault. This update modifies the underlying code to correctly
  deinitialize the data. (BZ#813079)

  * Previously, deinitialization of non-existent data could, in certain error
  cases, occur. As a result, rsyslogd could abort with a segmentation fault
  when rsyslog was configured to use a disk assisted queue without specify ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"rsyslog", rpm:"rsyslog~5.8.10~2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rsyslog-gnutls", rpm:"rsyslog-gnutls~5.8.10~2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rsyslog-gssapi", rpm:"rsyslog-gssapi~5.8.10~2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rsyslog-mysql", rpm:"rsyslog-mysql~5.8.10~2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rsyslog-pgsql", rpm:"rsyslog-pgsql~5.8.10~2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rsyslog-relp", rpm:"rsyslog-relp~5.8.10~2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rsyslog-snmp", rpm:"rsyslog-snmp~5.8.10~2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
