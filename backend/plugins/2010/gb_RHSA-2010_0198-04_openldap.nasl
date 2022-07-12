###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for openldap RHSA-2010:0198-04
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
  Protocol) applications and development tools.

  A flaw was found in the way OpenLDAP handled NUL characters in the
  CommonName field of X.509 certificates. An attacker able to get a
  carefully-crafted certificate signed by a trusted Certificate Authority
  could trick applications using OpenLDAP libraries into accepting it by
  mistake, allowing the attacker to perform a man-in-the-middle attack.
  (CVE-2009-3767)
  
  This update also fixes the following bugs:
  
  * the ldap init script did not provide a way to alter system limits for the
  slapd daemon. A variable is now available in &quot;/etc/sysconfig/ldap&quot; for this
  option. (BZ#527313)
  
  * applications that use the OpenLDAP libraries to contact a Microsoft
  Active Directory server could crash when a large number of network
  interfaces existed. This update implements locks in the OpenLDAP library
  code to resolve this issue. (BZ#510522)
  
  * when slapd was configured to allow client certificates, approximately 90%
  of connections froze because of a large CA certificate file and slapd not
  checking the success of the SSL handshake. (BZ#509230)
  
  * the OpenLDAP server would freeze for unknown reasons under high load.
  These packages add support for accepting incoming connections by new
  threads, resolving the issue. (BZ#507276)
  
  * the compat-openldap libraries did not list dependencies on other
  libraries, causing programs that did not specifically specify the libraries
  to fail. Detection of the Application Binary Interface (ABI) in use on
  64-bit systems has been added with this update. (BZ#503734)
  
  * the OpenLDAP libraries caused applications to crash due to an unprocessed
  network timeout. A timeval of -1 is now passed when NULL is passed to LDAP.
  (BZ#495701)
  
  * slapd could crash on a server under heavy load when using rwm overlay,
  caused by freeing non-allocated memory during operation cleanup.
  (BZ#495628)
  
  * the ldap init script made a temporary script in &quot;/tmp/&quot; and attempted to
  execute it. Problems arose when &quot;/tmp/&quot; was mounted with the noexec option.
  The temporary script is no longer created. (BZ#483356)
  
  * the ldap init script always started slapd listening on ldap:/// even if
  instructed to listen only on ldaps:///. By correcting the init script, a
  user can now select which ports slapd should listen on. (BZ#481003)
  
  * the slapd manual page did not mention the supported options -V and -o.
  (BZ#468206)
  
  * slapd.conf had a commented-out op ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "openldap on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-March/msg00031.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313598");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-06 08:56:44 +0200 (Tue, 06 Apr 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2010:0198-04");
  script_cve_id("CVE-2009-3767");
  script_name("RedHat Update for openldap RHSA-2010:0198-04");

  script_tag(name: "summary" , value: "Check for the Version of openldap");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"compat-openldap", rpm:"compat-openldap~2.3.43_2.2.29~12.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.3.43~12.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.3.43~12.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-debuginfo", rpm:"openldap-debuginfo~2.3.43~12.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-devel", rpm:"openldap-devel~2.3.43~12.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.3.43~12.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers-overlays", rpm:"openldap-servers-overlays~2.3.43~12.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers-sql", rpm:"openldap-servers-sql~2.3.43~12.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
