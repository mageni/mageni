###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for httpd RHSA-2015:1249-02
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
  script_oid("1.3.6.1.4.1.25623.1.0.871402");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2013-5704");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"creation_date", value:"2015-07-23 06:25:38 +0200 (Thu, 23 Jul 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for httpd RHSA-2015:1249-02");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The httpd packages provide the Apache HTTP Server, a powerful, efficient,
and extensible web server.

A flaw was found in the way httpd handled HTTP Trailer headers when
processing requests using chunked encoding. A malicious client could use
Trailer headers to set additional HTTP headers after header processing was
performed by other modules. This could, for example, lead to a bypass of
header restrictions defined with mod_headers. (CVE-2013-5704)

This update also fixes the following bugs:

  * The order of mod_proxy workers was not checked when httpd configuration
was reloaded. When mod_proxy workers were removed, added, or their order
was changed, their parameters and scores could become mixed. The order of
mod_proxy workers has been made internally consistent during configuration
reload. (BZ#1149906)

  * The local host certificate created during firstboot contained CA
extensions, which caused the httpd service to return warning messages.
This has been addressed by local host certificates being generated with the
'-extensions v3_req' option. (BZ#906476)

  * The default mod_ssl configuration no longer enables support for SSL
cipher suites using the single DES, IDEA, or SEED encryption algorithms.
(BZ#1086771)

  * The apachectl script did not take into account the HTTPD_LANG variable
set in the /etc/sysconfig/httpd file during graceful restarts.
Consequently, httpd did not use a changed value of HTTPD_LANG when the
daemon was restarted gracefully. The script has been fixed to handle the
HTTPD_LANG variable correctly. (BZ#963146)

  * The mod_deflate module failed to check the original file size while
extracting files larger than 4 GB, making it impossible to extract large
files. Now, mod_deflate checks the original file size properly according to
RFC1952, and it is able to decompress files larger than 4 GB. (BZ#1057695)

  * The httpd service did not check configuration before restart. When a
configuration contained an error, an attempt to restart httpd gracefully
failed. Now, httpd checks configuration before restart and if the
configuration is in an inconsistent state, an error message is printed,
httpd is not stopped and a restart is not performed. (BZ#1146194)

  * The SSL_CLIENT_VERIFY environment variable was incorrectly handled when
the 'SSLVerifyClient optional_no_ca' and 'SSLSessionCache' options were
used. When an SSL session was resumed, the SSL_CLIENT_VERIFY value was set
to 'SUCCESS' instead of the previously set 'GENEROUS'. SSL_CLIENT_VERIFY is
now correctly set to GENEROUS i ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"httpd on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-July/msg00018.html");
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

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.15~45.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.2.15~45.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.15~45.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.2.15~45.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.15~45.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.15~45.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
