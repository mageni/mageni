###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for ipa RHSA-2017:0388-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871767");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-03-03 05:49:35 +0100 (Fri, 03 Mar 2017)");
  script_cve_id("CVE-2017-2590");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for ipa RHSA-2017:0388-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipa'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Red Hat Identity Management (IdM) is a
centralized authentication, identity management, and authorization solution for
both traditional and cloud-based enterprise environments.

Security Fix(es):

  * It was found that IdM's ca-del, ca-disable, and ca-enable commands did
not properly check the user's permissions while modifying CAs in Dogtag. An
authenticated, unauthorized attacker could use this flaw to delete,
disable, or enable CAs causing various denial of service problems with
certificate issuance, OCSP signing, and deletion of secret keys.
(CVE-2017-2590)

This issue was discovered by Fraser Tweedale (Red Hat).

Bug Fix(es):

  * Previously, during an Identity Management (IdM) replica installation that
runs on domain level '1' or higher, Directory Server was not configured to
use TLS encryption. As a consequence, installing a certificate authority
(CA) on that replica failed. Directory Server is now configured to use TLS
encryption during the replica installation and as a result, the CA
installation works as expected. (BZ#1410760)

  * Previously, the Identity Management (IdM) public key infrastructure (PKI)
component was configured to listen on the '::1' IPv6 localhost address. In
environments have the the IPv6 protocol disabled, the replica installer was
unable to retrieve the Directory Server certificate, and the installation
failed. The default listening address of the PKI connector has been updated
from the IP address to 'localhost'. As a result, the PKI connector now
listens on the correct addresses in IPv4 and IPv6 environments.
(BZ#1416481)

  * Previously, when installing a certificate authority (CA) on a replica,
Identity Management (IdM) was unable to provide third-party CA certificates
to the Certificate System CA installer. As a consequence, the installer was
unable to connect to the remote master if the remote master used a
third-party server certificate, and the installation failed. This updates
applies a patch and as a result, installing a CA replica works as expected
in the described situation. (BZ#1415158)

  * When installing a replica, the web server service entry is created on the
Identity Management (IdM) master and replicated to all IdM servers.
Previously, when installing a replica without a certificate authority (CA),
in certain situations the service entry was not replicated to the new
replica on time, and the installation failed. The replica installer has
been updated and now waits until the web server service entry is
replicated. As a result, the replica installation no longer fails in the
described situation. (BZ#1416488)");
  script_tag(name:"affected", value:"ipa on
  Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-March/msg00010.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"ipa-admintools", rpm:"ipa-admintools~4.4.0~14.el7_3.6", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-client-common", rpm:"ipa-client-common~4.4.0~14.el7_3.6", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-common", rpm:"ipa-common~4.4.0~14.el7_3.6", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-python-compat", rpm:"ipa-python-compat~4.4.0~14.el7_3.6", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server-common", rpm:"ipa-server-common~4.4.0~14.el7_3.6", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server-dns", rpm:"ipa-server-dns~4.4.0~14.el7_3.6", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python2-ipaclient", rpm:"python2-ipaclient~4.4.0~14.el7_3.6", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python2-ipalib", rpm:"python2-ipalib~4.4.0~14.el7_3.6", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python2-ipaserver", rpm:"python2-ipaserver~4.4.0~14.el7_3.6", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~4.4.0~14.el7_3.6", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-debuginfo", rpm:"ipa-debuginfo~4.4.0~14.el7_3.6", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~4.4.0~14.el7_3.6", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server-trust-ad", rpm:"ipa-server-trust-ad~4.4.0~14.el7_3.6", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
