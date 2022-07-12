###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for ipa RHSA-2015:1462-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871399");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2010-5312", "CVE-2012-6662");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-07-23 06:25:10 +0200 (Thu, 23 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for ipa RHSA-2015:1462-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipa'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Two cross-site scripting (XSS) flaws were found in jQuery, which impacted
the Identity Management web administrative interface, and could allow an
authenticated user to inject arbitrary HTML or web script into the
interface. (CVE-2010-5312, CVE-2012-6662)

Note: The IdM version provided by this update no longer uses jQuery.

Bug fixes:

  * The ipa-server-install, ipa-replica-install, and ipa-client-install
utilities are not supported on machines running in FIPS-140 mode.
Previously, IdM did not warn users about this. Now, IdM does not allow
running the utilities in FIPS-140 mode, and displays an explanatory
message. (BZ#1131571)

  * If an Active Directory (AD) server was specified or discovered
automatically when running the ipa-client-install utility, the utility
produced a traceback instead of informing the user that an IdM server is
expected in this situation. Now, ipa-client-install detects the AD server
and fails with an explanatory message. (BZ#1132261)

  * When IdM servers were configured to require the TLS protocol version 1.1
(TLSv1.1) or later in the httpd server, the ipa utility failed. With this
update, running ipa works as expected with TLSv1.1 or later. (BZ#1154687)

  * In certain high-load environments, the Kerberos authentication step of
the IdM client installer can fail. Previously, the entire client
installation failed in this situation. This update modifies
ipa-client-install to prefer the TCP protocol over the UDP protocol and to
retry the authentication attempt in case of failure. (BZ#1161722)

  * If ipa-client-install updated or created the /etc/nsswitch.conf file, the
sudo utility could terminate unexpectedly with a segmentation fault. Now,
ipa-client-install puts a new line character at the end of nsswitch.conf if
it modifies the last line of the file, fixing this bug. (BZ#1185207)

  * The ipa-client-automount utility failed with the 'UNWILLING_TO_PERFORM'
LDAP error when the nsslapd-minssf Red Hat Directory Server configuration
parameter was set to '1'. This update modifies ipa-client-automount to use
encrypted connection for LDAP searches by default, and the utility now
finishes successfully even with nsslapd-minssf specified. (BZ#1191040)

  * If installing an IdM server failed after the Certificate Authority (CA)
installation, the 'ipa-server-install --uninstall' command did not perform
a proper cleanup. After the user issued 'ipa-server-install --uninstall'
and then attempted to install the server again, the installation failed.
Now, 'ipa-server-install --uninst ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"ipa on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-July/msg00038.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"ipa-admintools", rpm:"ipa-admintools~3.0.0~47.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~3.0.0~47.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-debuginfo", rpm:"ipa-debuginfo~3.0.0~47.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-python", rpm:"ipa-python~3.0.0~47.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~3.0.0~47.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server-selinux", rpm:"ipa-server-selinux~3.0.0~47.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server-trust-ad", rpm:"ipa-server-trust-ad~3.0.0~47.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
