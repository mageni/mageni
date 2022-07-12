###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for sssd RHSA-2013:1319-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871049");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-10-03 10:17:50 +0530 (Thu, 03 Oct 2013)");
  script_cve_id("CVE-2013-0219");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for sssd RHSA-2013:1319-01");


  script_tag(name:"affected", value:"sssd on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"insight", value:"SSSD (System Security Services Daemon) provides a set of daemons to manage
access to remote directories and authentication mechanisms. It provides NSS
(Name Service Switch) and PAM (Pluggable Authentication Modules) interfaces
toward the system and a pluggable back end system to connect to multiple
different account sources.

A race condition was found in the way SSSD copied and removed user home
directories. A local attacker who is able to write into the home directory
of a different user who is being removed could use this flaw to perform
symbolic link attacks, possibly allowing them to modify and delete
arbitrary files with the privileges of the root user. (CVE-2013-0219)

The CVE-2013-0219 issue war discovered by Florian Weimer of the Red Hat
Product Security Team.

This update also fixes the following bugs:

  * After a paging control was used, memory in the sssd_be process was never
freed which led to the growth of the sssd_be process memory usage over
time. To fix this bug, the paging control was deallocated after use, and
thus the memory usage of the sssd_be process no longer grows. (BZ#820908)

  * If the sssd_be process was terminated and recreated while there were
authentication requests pending, the sssd_pam process did not recover
correctly and did not reconnect to the new sssd_be process. Consequently,
the sssd_pam process was seemingly blocked and did not accept any new
authentication requests. The sssd_pam process has been fixes so that it
reconnects to the new instance of the sssd_be process after the original
one terminated unexpectedly. Even after a crash and reconnect, the sssd_pam
process now accepts new authentication requests. (BZ#882414)

  * When the sssd_be process hung for a while, it was terminated and a new
instance was created. If the old instance did not respond to the TERM
signal and continued running, SSSD terminated unexpectedly. As a
consequence, the user could not log in. SSSD now keeps track of sssd_be
subprocesses more effectively, making the restarts of sssd_be more reliable
in such scenarios. Users can now log in whenever the sssd_be is restarted
and becomes unresponsive. (BZ#886165)

  * In case the processing of an LDAP request took longer than the client
timeout upon completing the request (60 seconds by default), the PAM client
could have accessed memory that was previously freed due to the client
timeout being reached. As a result, the sssd_pam process terminated
unexpectedly with a segmentation fault. SSSD now ignores an LDAP request
result when it detects that the set timeout of this request has been
reached. The sssd_pam process n ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-September/msg00052.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'sssd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"libipa_hbac", rpm:"libipa_hbac~1.5.1~70.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libipa_hbac-devel", rpm:"libipa_hbac-devel~1.5.1~70.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libipa_hbac-python", rpm:"libipa_hbac-python~1.5.1~70.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.5.1~70.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-client", rpm:"sssd-client~1.5.1~70.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-debuginfo", rpm:"sssd-debuginfo~1.5.1~70.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.5.1~70.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
