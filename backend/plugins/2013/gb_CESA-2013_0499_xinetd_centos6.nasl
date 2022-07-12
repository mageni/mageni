###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for xinetd CESA-2013:0499 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019552.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881672");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-12 10:02:07 +0530 (Tue, 12 Mar 2013)");
  script_cve_id("CVE-2012-0862");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("CentOS Update for xinetd CESA-2013:0499 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xinetd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"xinetd on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The xinetd package provides a secure replacement for inetd, the Internet
  services daemon. xinetd provides access control for all services based on
  the address of the remote host and/or on time of access, and can prevent
  denial-of-access attacks.

  When xinetd services are configured with the type,
  and the tcpmux-server service is enabled, those services are accessible via
  port 1. It was found that enabling the tcpmux-server service (it is
  disabled by default) allowed every xinetd service, including those that are
  not configured with the type, to be accessible via port 1. This could allow
  a remote attacker to bypass intended firewall restrictions. (CVE-2012-0862)

  Red Hat would like to thank Thomas Swan of FedEx for reporting this issue.

  This update also fixes the following bugs:

  * Prior to this update, a file descriptor array in the service.c source
  file was not handled as expected. As a consequence, some of the descriptors
  remained open when xinetd was under heavy load. Additionally, the system
  log was filled with a large number of messages that took up a lot of disk
  space over time. This update modifies the xinetd code to handle the file
  descriptors correctly and messages no longer fill the system log.
  (BZ#790036)

  * Prior to this update, services were disabled permanently when their CPS
  limit was reached. As a consequence, a failed bind operation could occur
  when xinetd attempted to restart the service. This update adds additional
  logic that attempts to restart the service. Now, the service is only
  disabled if xinetd cannot restart the service after 30 attempts.
  (BZ#809271)

  All users of xinetd are advised to upgrade to this updated package, which
  contains backported patches to correct these issues.");
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

  if ((res = isrpmvuln(pkg:"xinetd", rpm:"xinetd~2.3.14~38.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
