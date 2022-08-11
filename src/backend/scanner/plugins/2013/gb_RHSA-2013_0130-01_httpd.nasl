###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for httpd RHSA-2013:0130-01
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
  script_tag(name:"affected", value:"httpd on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The httpd packages contain the Apache HTTP Server (httpd), which is the
  namesake project of The Apache Software Foundation.

  Input sanitization flaws were found in the mod_negotiation module. A remote
  attacker able to upload or create files with arbitrary names in a directory
  that has the MultiViews options enabled, could use these flaws to conduct
  cross-site scripting and HTTP response splitting attacks against users
  visiting the site. (CVE-2008-0455, CVE-2008-0456, CVE-2012-2687)

  Bug fixes:

  * Previously, no check was made to see if the
  /etc/pki/tls/private/localhost.key file was a valid key prior to running
  the '%post' script for the 'mod_ssl' package. Consequently, when
  /etc/pki/tls/certs/localhost.crt did not exist and 'localhost.key' was
  present but invalid, upgrading the Apache HTTP Server daemon (httpd) with
  mod_ssl failed. The '%post' script has been fixed to test for an existing
  SSL key. As a result, upgrading httpd with mod_ssl now proceeds as
  expected. (BZ#752618)

  * The 'mod_ssl' module did not support operation under FIPS mode.
  Consequently, when operating Red Hat Enterprise Linux 5 with FIPS mode
  enabled, httpd failed to start. An upstream patch has been applied to
  disable non-FIPS functionality if operating under FIPS mode and httpd now
  starts as expected. (BZ#773473)

  Description truncated, please see the referenced URL(s) for more information.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-January/msg00013.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870882");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-01-11 16:42:23 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2008-0455", "CVE-2008-0456", "CVE-2012-2687");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("RedHat Update for httpd RHSA-2013:0130-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd'
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

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.3~74.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.2.3~74.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.3~74.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.3~74.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.3~74.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
