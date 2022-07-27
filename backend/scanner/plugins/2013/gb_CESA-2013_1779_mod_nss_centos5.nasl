###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for mod_nss CESA-2013:1779 centos5
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.881827");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-12-04 10:10:03 +0530 (Wed, 04 Dec 2013)");
  script_cve_id("CVE-2013-4566");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_name("CentOS Update for mod_nss CESA-2013:1779 centos5");

  script_tag(name:"affected", value:"mod_nss on CentOS 5");
  script_tag(name:"insight", value:"The mod_nss module provides strong cryptography for the Apache HTTP Server
via the Secure Sockets Layer (SSL) and Transport Layer Security (TLS)
protocols, using the Network Security Services (NSS) security library.

A flaw was found in the way mod_nss handled the NSSVerifyClient setting for
the per-directory context. When configured to not require a client
certificate for the initial connection and only require it for a specific
directory, mod_nss failed to enforce this requirement and allowed a client
to access the directory when no valid client certificate was provided.
(CVE-2013-4566)

Red Hat would like to thank Albert Smith of OUSD(AT&amp L) for reporting this
issue.

All mod_nss users should upgrade to this updated package, which contains a
backported patch to correct this issue. The httpd service must be restarted
for this update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-December/020039.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mod_nss'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"mod_nss", rpm:"mod_nss~1.0.8~8.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
