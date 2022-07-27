###############################################################################
# OpenVAS Vulnerability Test
# $Id: cvs_malformed_entry_lines_flaw.nasl 12011 2018-10-22 08:58:15Z cfischer $
#
# CVS malformed entry lines flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:cvs:cvs";

# Ref:
#  Date: Wed, 9 Jun 2004 15:00:04 +0200
#  From: Stefan Esser <s.esser@e-matters.de>
#  To: full-disclosure@lists.netsys.com, bugtraq@securityfocus.com,
#        red@heisec.de, news@golem.de
#  Subject: Advisory 09/2004: More CVS remote vulnerabilities

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12265");
  script_version("$Revision: 12011 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 10:58:15 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(10499);
  script_cve_id("CVE-2004-0414", "CVE-2004-0416", "CVE-2004-0417", "CVE-2004-0418");
  script_name("CVS malformed entry lines flaw");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("General");
  script_dependencies("cvspserver_version.nasl");
  script_mandatory_keys("cvspserver/detected");

  script_tag(name:"solution", value:"Upgrade to CVS 1.12.9 or 1.11.17.");

  script_tag(name:"summary", value:"The remote CVS server, according to its version number, might allow an
  attacker to execute arbitrary commands on the remote system because of a flaw relating to malformed Entry
  lines which lead to a missing NULL terminator.");

  script_tag(name:"insight", value:"Among the issues deemed likely to be exploitable were:

  - a double-free relating to the error_prog_name string (CVE-2004-0416)

  - an argument integer overflow (CVE-2004-0417)

  - out-of-bounds writes in serv_notify (CVE-2004-0418)");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.11.17" ) ||
    version_in_range( version:vers, test_version:"1.12", test_version2:"1.12.8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.11.17/1.12.9" );
  security_message( port:port, data:report );
}

exit( 0 );