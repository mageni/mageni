###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dovecot_mult_sec_bypass_vuln.nasl 12705 2018-12-07 13:38:36Z cfischer $
#
# Dovecot ACL Plugin Security Bypass Vulnerabilities
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:dovecot:dovecot";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800030");
  script_version("$Revision: 12705 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-07 14:38:36 +0100 (Fri, 07 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-10-17 14:35:03 +0200 (Fri, 17 Oct 2008)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2008-4577", "CVE-2008-4578");
  script_bugtraq_id(31587);
  script_name("Dovecot ACL Plugin Security Bypass Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2745");
  script_xref(name:"URL", value:"http://www.dovecot.org/list/dovecot-news/2008-October/000085.html");

  script_tag(name:"impact", value:"Successful attack could allow malicious people to bypass certain
  security restrictions or manipulate certain data.");

  script_tag(name:"affected", value:"Dovecot versions prior to 1.1.4 on Linux.");

  script_tag(name:"insight", value:"The flaws are due to,

  - the ACL plugin interprets negative access rights as positive access rights,
    potentially giving an unprivileged user access to restricted resources.

  - an error in the ACL plugin when imposing mailbox creation restrictions to
    to create parent/child/child mailboxes.");

  script_tag(name:"solution", value:"Upgrade to Dovecot version 1.1.4.");

  script_tag(name:"summary", value:"This host has Dovecot ACL Plugin installed and is prone to
  multiple security bypass vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"1.1.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.1.4" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );