###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for dovecot MDVSA-2008:232 (dovecot)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The ACL plugin in dovecot prior to version 1.1.4 treated negative
  access rights as though they were positive access rights, which allowed
  attackers to bypass intended access restrictions (CVE-2008-4577).

  The ACL plugin in dovecot prior to version 1.1.6 allowed attackers to
  bypass intended access restrictions by using the 'k' right to create
  unauthorized 'parent/child/child' mailboxes (CVE-2008-4578).
  
  In addition, two bugs were discovered in the dovecot package shipped
  with Mandriva Linux 2009.0. The default permissions on the dovecot.conf
  configuration file were too restrictive, which prevents the use of
  dovecot's 'deliver' command as a non-root user. Secondly, dovecot
  should not start until after ntpd, if ntpd is active, because if ntpd
  corrects the time backwards while dovecot is running, dovecot will
  quit automatically, with the log message 'Time just moved backwards
  by X seconds. This might cause a lot of problems, so I'll just kill
  myself now.' The update resolves both these problems. The default
  permissions on dovecot.conf now allow the 'deliver' command to read the
  file. Note that if you edited dovecot.conf at all prior to installing
  the update, the new permissions may not be applied. If you find the
  'deliver' command still does not work following the update, please
  run these commands as root:
  
  # chmod 0640 /etc/dovecot.conf
  # chown root:mail /etc/dovecot.conf
  
  Dovecot's initialization script now configures it to start after the
  ntpd service, to ensure ntpd resetting the clock does not interfere
  with Dovecot operation.
  
  This package corrects the above-noted bugs and security issues by
  upgrading to the latest dovecot 1.1.6, which also provides additional
  bug fixes.";

tag_affected = "dovecot on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-11/msg00016.php");
  script_oid("1.3.6.1.4.1.25623.1.0.309096");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:26:37 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_xref(name: "MDVSA", value: "2008:232");
  script_cve_id("CVE-2008-4577", "CVE-2008-4578");
  script_name( "Mandriva Update for dovecot MDVSA-2008:232 (dovecot)");

  script_tag(name:"summary", value:"Check for the Version of dovecot");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~1.1.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-devel", rpm:"dovecot-devel~1.1.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-gssapi", rpm:"dovecot-plugins-gssapi~1.1.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-ldap", rpm:"dovecot-plugins-ldap~1.1.6~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
