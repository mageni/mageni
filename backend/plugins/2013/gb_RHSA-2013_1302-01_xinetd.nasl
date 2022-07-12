###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for xinetd RHSA-2013:1302-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871043");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-10-03 10:17:04 +0530 (Thu, 03 Oct 2013)");
  script_cve_id("CVE-2012-0862");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("RedHat Update for xinetd RHSA-2013:1302-01");


  script_tag(name:"affected", value:"xinetd on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"insight", value:"The xinetd package provides a secure replacement for inetd, the Internet
services daemon. xinetd provides access control for all services based on
the address of the remote host and/or on time of access, and can prevent
denial-of-access attacks.

When xinetd services are configured with the 'TCPMUX' or 'TCPMUXPLUS' type,
and the tcpmux-server service is enabled, those services are accessible via
port 1. It was found that enabling the tcpmux-server service (it is
disabled by default) allowed every xinetd service, including those that are
not configured with the 'TCPMUX' or 'TCPMUXPLUS' type, to be accessible via
port 1. This could allow a remote attacker to bypass intended firewall
restrictions. (CVE-2012-0862)

Red Hat would like to thank Thomas Swan of FedEx for reporting this issue.

This update also fixes the following bugs:

  * Prior to this update, a file descriptor array in the service.c source
file was not handled as expected. As a consequence, some of the descriptors
remained open when xinetd was under heavy load. Additionally, the system
log was filled with a large number of messages that took up a lot of disk
space over time. This update modifies the xinetd code to handle the file
descriptors correctly and messages no longer fill the system log.
(BZ#852274)

  * Prior to this update, services were disabled permanently when their CPS
limit was reached. As a consequence, a failed bind operation could occur
when xinetd attempted to restart the service. This update adds additional
logic that attempts to restart the service. Now, the service is only
disabled if xinetd cannot restart the service after 30 attempts.
(BZ#811000)

All users of xinetd are advised to upgrade to this updated package, which
contains backported patches to correct these issues.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-September/msg00049.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xinetd'
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

  if ((res = isrpmvuln(pkg:"xinetd", rpm:"xinetd~2.3.14~19.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xinetd-debuginfo", rpm:"xinetd-debuginfo~2.3.14~19.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
