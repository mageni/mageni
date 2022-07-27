###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for openldap RHSA-2015:2131-03
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
  script_oid("1.3.6.1.4.1.25623.1.0.871489");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 06:21:30 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2015-3276");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for openldap RHSA-2015:2131-03");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenLDAP is an open-source suite of Lightweight
Directory Access Protocol (LDAP) applications and development tools. LDAP is a set
of protocols used to access and maintain distributed directory information services
over an IP network. The openldap packages contain configuration files, libraries,
and documentation for OpenLDAP.

A flaw was found in the way OpenLDAP parsed OpenSSL-style cipher strings.
As a result, OpenLDAP could potentially use ciphers that were not intended
to be enabled. (CVE-2015-3276)

This issue was discovered by Martin Poole of the Red Hat Software
Maintenance Engineering group.

The openldap packages have been upgraded to upstream version 2.4.40, which
provides a number of bug fixes and one enhancement over the previous
version:

  * The ORDERING matching rules have been added to the ppolicy attribute type
descriptions.

  * The server no longer terminates unexpectedly when processing SRV records.

  * Missing objectClass information has been added, which enables the user to
modify the front-end configuration by standard means.

(BZ#1147982)

This update also fixes the following bugs:

  * Previously, OpenLDAP did not properly handle a number of simultaneous
updates. As a consequence, sending a number of parallel update requests to
the server could cause a deadlock. With this update, a superfluous locking
mechanism causing the deadlock has been removed, thus fixing the bug.
(BZ#1125152)

  * The httpd service sometimes terminated unexpectedly with a segmentation
fault on the libldap library unload. The underlying source code has been
modified to prevent a bad memory access error that caused the bug to occur.
As a result, httpd no longer crashes in this situation. (BZ#1158005)

  * After upgrading the system from Red Hat Enterprise Linux 6 to Red Hat
Enterprise Linux 7, symbolic links to certain libraries unexpectedly
pointed to locations belonging to the openldap-devel package. If the user
uninstalled openldap-devel, the symbolic links were broken and the 'rpm -V
openldap' command sometimes produced errors. With this update, the symbolic
links no longer get broken in the described situation. If the user
downgrades openldap to version 2.4.39-6 or earlier, the symbolic links
might break. After such downgrade, it is recommended to verify that the
symbolic links did not break. To do this, make sure the yum-plugin-verify
package is installed and obtain the target libraries by running the 'rpm -V
openldap' or 'yum verify openldap' command. (BZ#1230263)

In addition, this update adds the following enhancement:

  * OpenLDAP clients now automatically choose the Netwo ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"openldap on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00022.html");
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

  if ((res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.4.40~8.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.4.40~8.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-debuginfo", rpm:"openldap-debuginfo~2.4.40~8.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-devel", rpm:"openldap-devel~2.4.40~8.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.4.40~8.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
