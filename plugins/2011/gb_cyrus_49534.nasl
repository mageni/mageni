###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cyrus_49534.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Cyrus IMAP Server 'split_wildmats()' Remote Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:cmu:cyrus_imap_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103249");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-12 14:00:02 +0200 (Mon, 12 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-3208");
  script_bugtraq_id(49534);
  script_name("Cyrus IMAP Server 'split_wildmats()' Remote Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_cyrus_imap_server_detect.nasl");
  script_require_ports("Services/imap", 143, "Services/pop3", 110);
  script_mandatory_keys("Cyrus/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49534");
  script_xref(name:"URL", value:"http://asg.andrew.cmu.edu/archive/message.php?mailbox=archive.cyrus-announce&msg=199");
  script_xref(name:"URL", value:"http://asg.andrew.cmu.edu/archive/message.php?mailbox=archive.cyrus-announce&msg=200");
  script_xref(name:"URL", value:"http://cyrusimap.web.cmu.edu/");

  script_tag(name:"impact", value:"Attackers can execute arbitrary code in the context of the affected
  application. Failed exploit attempts will result in a denial-of-service condition.");
  script_tag(name:"affected", value:"Cyrus IMAP Server versions prior to 2.3.17 and 2.4.11 are vulnerable.");
  script_tag(name:"summary", value:"Cyrus IMAP Server is prone to a remote buffer-overflow vulnerability because the
  application fails to properly bounds check user-supplied data before copying it into an
  insufficiently sized buffer.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"2.4", test_version2:"2.4.10" ) ||
    version_in_range( version:vers, test_version:"2.3", test_version2:"2.3.16" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.3.17/2.4.11" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
