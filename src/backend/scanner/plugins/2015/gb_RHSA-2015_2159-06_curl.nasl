###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for curl RHSA-2015:2159-06
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
  script_oid("1.3.6.1.4.1.25623.1.0.871491");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 06:21:32 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2014-3613", "CVE-2014-3707", "CVE-2014-8150", "CVE-2015-3143",
                "CVE-2015-3148");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for curl RHSA-2015:2159-06");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The curl packages provide the libcurl
library and the curl utility for downloading files from servers using various
protocols, including HTTP, FTP, and LDAP.

It was found that the libcurl library did not correctly handle partial
literal IP addresses when parsing received HTTP cookies. An attacker able
to trick a user into connecting to a malicious server could use this flaw
to set the user's cookie to a crafted domain, making other cookie-related
issues easier to exploit. (CVE-2014-3613)

A flaw was found in the way the libcurl library performed the duplication
of connection handles. If an application set the CURLOPT_COPYPOSTFIELDS
option for a handle, using the handle's duplicate could cause the
application to crash or disclose a portion of its memory. (CVE-2014-3707)

It was discovered that the libcurl library failed to properly handle URLs
with embedded end-of-line characters. An attacker able to make an
application using libcurl access a specially crafted URL via an HTTP proxy
could use this flaw to inject additional headers to the request or
construct additional requests. (CVE-2014-8150)

It was discovered that libcurl implemented aspects of the NTLM and
Negotatiate authentication incorrectly. If an application uses libcurl
and the affected mechanisms in a specific way, certain requests to a
previously NTLM-authenticated server could appears as sent by the wrong
authenticated user. Additionally, the initial set of credentials for HTTP
Negotiate-authenticated requests could be reused in subsequent requests,
although a different set of credentials was specified. (CVE-2015-3143,
CVE-2015-3148)

Red Hat would like to thank the cURL project for reporting these issues.

Bug fixes:

  * An out-of-protocol fallback to SSL 3.0 was available with libcurl.
Attackers could abuse the fallback to force downgrade of the SSL version.
The fallback has been removed from libcurl. Users requiring this
functionality can explicitly enable SSL 3.0 through the libcurl API.
(BZ#1154060)

  * TLS 1.1 and TLS 1.2 are no longer disabled by default in libcurl. You can
explicitly disable them through the libcurl API. (BZ#1170339)

  * FTP operations such as downloading files took a significantly long time
to complete. Now, the FTP implementation in libcurl correctly sets blocking
direction and estimated timeout for connections, resulting in faster FTP
transfers. (BZ#1218272)

Enhancements:

  * With the updated packages, it is possible to explicitly enable or disable
new Advanced Encryption Standard (AES) cipher suites to be used for the TLS
protocol. (BZ#1066065)

  * The libcurl library did not impleme ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"curl on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00028.html");
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

  if ((res = isrpmvuln(pkg:"curl", rpm:"curl~7.29.0~25.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"curl-debuginfo", rpm:"curl-debuginfo~7.29.0~25.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.29.0~25.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.29.0~25.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
