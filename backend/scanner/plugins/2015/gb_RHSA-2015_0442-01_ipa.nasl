###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for ipa RHSA-2015:0442-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871321");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-03-06 06:48:59 +0100 (Fri, 06 Mar 2015)");
  script_cve_id("CVE-2010-5312", "CVE-2012-6662");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for ipa RHSA-2015:0442-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipa'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Red Hat Identity Management (IdM) is a centralized authentication, identity
management, and authorization solution for both traditional and cloud-based
enterprise environments.

Two cross-site scripting (XSS) flaws were found in jQuery, which impacted
the Identity Management web administrative interface, and could allow an
authenticated user to inject arbitrary HTML or web script into the
interface. (CVE-2010-5312, CVE-2012-6662)

Note: The IdM version provided by this update no longer uses jQuery.

This update adds several enhancements that are described in more detail in
the Red Hat Enterprise Linux 7.1 Release Notes, linked to in the References
section, including:

  * Added the 'ipa-cacert-manage' command, which renews the Certification
Authority (CA) file. (BZ#886645)

  * Added the ID Views feature. (BZ#891984)

  * IdM now supports using one-time password (OTP) authentication and allows
gradual migration from proprietary OTP solutions to the IdM OTP solution.
(BZ#919228)

  * Added the 'ipa-backup' and 'ipa-restore' commands to allow manual
backups. (BZ#951581)

  * Added a solution for regulating access permissions to specific sections
of the IdM server. (BZ#976382)

This update also fixes several bugs, including:

  * Previously, when IdM servers were configured to require the Transport
Layer Security protocol version 1.1 (TLSv1.1) or later in the httpd server,
the 'ipa' command-line utility failed. With this update, running 'ipa'
works as expected with TLSv1.1 or later. (BZ#1156466)

In addition, this update adds multiple enhancements, including:

  * The 'ipa-getkeytab' utility can now optionally fetch existing keytabs
from the KDC. Previously, retrieving an existing keytab was not supported,
as the only option was to generate a new key. (BZ#1007367)

  * You can now create and manage a '.' root zone on IdM servers. DNS queries
sent to the IdM DNS server use this configured zone instead of the public
zone. (BZ#1056202)

  * The IdM server web UI has been updated and is now based on the Patternfly
framework, offering better responsiveness. (BZ#1108212)

  * A new user attribute now enables provisioning systems to add custom tags
for user objects. The tags can be used for automember rules or for
additional local interpretation. (BZ#1108229)

  * This update adds a new DNS zone type to ensure that forward and master
zones are better separated. As a result, the IdM DNS interface complies
with the forward zone semantics in BIND. (BZ#1114013)

  * This update adds a set of Apache modules that external applications can
use to achieve tighter interaction with IdM beyond simple authentication ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"ipa on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-March/msg00011.html");
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

  if ((res = isrpmvuln(pkg:"ipa-admintools", rpm:"ipa-admintools~4.1.0~18.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~4.1.0~18.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-debuginfo", rpm:"ipa-debuginfo~4.1.0~18.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-python", rpm:"ipa-python~4.1.0~18.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~4.1.0~18.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server-trust-ad", rpm:"ipa-server-trust-ad~4.1.0~18.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
