###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for squid RHSA-2013:0505-02
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-February/msg00048.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870912");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-02-22 10:01:14 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2012-5643");
  script_bugtraq_id(56957);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for squid RHSA-2013:0505-02");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"squid on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Squid is a high-performance proxy caching server for web clients that
  supports FTP, Gopher, and HTTP data objects.

  A denial of service flaw was found in the way the Squid Cache Manager
  processed certain requests. A remote attacker who is able to access the
  Cache Manager CGI could use this flaw to cause Squid to consume an
  excessive amount of memory. (CVE-2012-5643)

  This update also fixes the following bugs:

  * Due to a bug in the ConnStateData::noteMoreBodySpaceAvailable() function,
  child processes of Squid terminated upon encountering a failed assertion.
  An upstream patch has been provided and Squid child processes no longer
  terminate. (BZ#805879)

  * Due to an upstream patch, which renamed the HTTP header controlling
  persistent connections from Proxy-Connection to Connection, the NTLM
  pass-through authentication does not work, thus preventing login. This
  update adds the new http10 option to the squid.conf file, which can be
  used to enable the change in the patch. This option is set to off by
  default. When set to on, the NTLM pass-through authentication works
  properly, thus allowing login attempts to succeed. (BZ#844723)

  * When the IPv6 protocol was disabled and Squid tried to handle an HTTP GET
  request containing an IPv6 address, the Squid child process terminated due
  to signal 6. This bug has been fixed and such requests are now handled as
  expected. (BZ#832484)

  * The old stale if hit logic did not account for cases where the stored
  stale response became fresh due to a successful re-validation with the
  origin server. Consequently, incorrect warning messages were returned. Now,
  Squid no longer marks elements as stale in the described scenario.
  (BZ#847056)

  * When squid packages were installed before samba-winbind, the wbpriv group
  did not include Squid. Consequently, NTLM authentication calls failed. Now,
  Squid correctly adds itself into the wbpriv group if samba-winbind is
  installed before Squid, thus fixing this bug. (BZ#797571)

  * In FIPS mode, Squid was using private MD5 hash functions for user
  authentication and network access. As MD5 is incompatible with FIPS mode,
  Squid could fail to start. This update limits the use of the private MD5
  functions to local disk file hash identifiers, thus allowing Squid to work
  in FIPS mode. (BZ#833086)

  * Under high system load, the squid process could terminate unexpectedly
  with a segmentation fault during reboot. T ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"squid", rpm:"squid~3.1.10~16.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squid-debuginfo", rpm:"squid-debuginfo~3.1.10~16.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
